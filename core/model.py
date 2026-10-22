"""Shared path calculation, independent of Ryu and Containernet."""

import heapq
import math


def adaptive_weights(energy_fraction, threshold=0.20, steepness=15.0,
                     delay_share=0.70):
    """Return experimental (alpha, beta, gamma) from a logistic energy weight.

    beta = 1 / (1 + exp(steepness * (energy_fraction - threshold))).
    alpha and gamma split the remaining weight using delay_share.
    Parameters are lab design choices, not constants established by a standard.
    beta increases as battery decreases, but the resulting weighted COST is
    not necessarily monotone with battery: delay/carbon weights also change.
    This function alone implements no threshold exclusion or energy saving.
    """
    values = (energy_fraction, threshold, steepness, delay_share)
    if not all(math.isfinite(value) for value in values):
        raise ValueError("Adaptive-weight inputs must be finite")
    if not 0 <= energy_fraction <= 1 or not 0 <= threshold <= 1:
        raise ValueError("Energy fraction and threshold must be in [0, 1]")
    if steepness <= 0 or not 0 <= delay_share <= 1:
        raise ValueError("Steepness must be positive and delay share in [0, 1]")

    # Stable evaluation: exp() always receives a nonpositive argument.
    x = steepness * (energy_fraction - threshold)
    if x >= 0:
        decay = math.exp(-x)
        beta = decay / (1.0 + decay)
    else:
        decay = math.exp(x)
        beta = 1.0 / (1.0 + decay)
    remainder = 1.0 - beta
    return (delay_share * remainder, beta, (1.0 - delay_share) * remainder)


def uav_cost(delay_ms, energy_fraction, carbon_norm, delay_budget_ms, weights):
    """Return a normalized weighted relay cost, not a QoS admission decision.

    energy_fraction is residual battery energy divided by full capacity.
    carbon_norm is a dimensionless carbon index on a fixed common scale [0, 1].
    delay_ms is the one-way delay attributed to this UAV traversal.
    weights contains (alpha, beta, gamma), nonnegative and summing to one.
    Delay is divided by the end-to-end one-way flow budget and is not clipped.
    """
    alpha, beta, gamma = weights
    values = (delay_ms, energy_fraction, carbon_norm, delay_budget_ms,
              alpha, beta, gamma)
    if not all(math.isfinite(value) for value in values):
        raise ValueError("Cost inputs must be finite")
    if delay_ms < 0 or delay_budget_ms <= 0:
        raise ValueError("Delay must be nonnegative and its budget positive")
    if not 0 <= energy_fraction <= 1 or not 0 <= carbon_norm <= 1:
        raise ValueError("Energy fraction and normalized carbon must be in [0, 1]")
    if min(alpha, beta, gamma) < 0 or not math.isclose(
        alpha + beta + gamma, 1.0, rel_tol=0.0, abs_tol=1e-9
    ):
        raise ValueError("Weights must be nonnegative and sum to one")

    delay_norm = delay_ms / delay_budget_ms
    energy_penalty = 1.0 - energy_fraction
    return alpha * delay_norm + beta * energy_penalty + gamma * carbon_norm


def capacity_filtered_links(links, capacities_mbps, reserved_mbps, required_mbps):
    """Return links excluding relays without enough capacity in ONE direction.

    capacities_mbps maps relay names to capacity; endpoints are not in that map.
    reserved_mbps supplies existing reservations for the direction being tested.
    All rates must use the same bandwidth accounting basis. No state is mutated.
    This handles capacity only, not end-to-end delay, loss or scheduling.
    """
    if not math.isfinite(required_mbps) or required_mbps <= 0:
        raise ValueError("GBR demand must be positive and finite")
    if set(reserved_mbps) - set(capacities_mbps):
        raise ValueError("Reservation supplied for an unknown relay")

    blocked = set()
    for relay, capacity in capacities_mbps.items():
        reserved = reserved_mbps.get(relay, 0.0)
        if not math.isfinite(capacity) or capacity < 0:
            raise ValueError("Capacity must be finite and nonnegative")
        if not math.isfinite(reserved) or reserved < 0 or reserved > capacity:
            raise ValueError("Reservation must be between zero and capacity")
        if capacity - reserved < required_mbps:
            blocked.add(relay)

    return [(first, second) for first, second in links
            if first not in blocked and second not in blocked]


class NoFeasiblePath(ValueError):
    """No path satisfies the supplied topology and delay bound."""


def feasible_path(links, source, destination, edge_cost, edge_delay,
                  delay_budget_ms):
    """Return (path, cost, delay_ms) with minimum cost within a delay bound.

    Supply capacity-filtered links to enforce capacity as well. Callbacks
    provide nonnegative directed costs and one-way delays, frozen per call.
    This exact search considers simple paths and prunes over-budget or
    already-more-expensive prefixes. It is intended for our small lab graph;
    worst-case search grows exponentially, unlike ordinary Dijkstra.
    No reservations or network rules are changed here. Configured delay
    feasibility does not bound real queueing or guarantee measured QoS.
    """
    if not math.isfinite(delay_budget_ms) or delay_budget_ms <= 0:
        raise ValueError("Delay budget must be positive and finite")

    graph = {}
    for first, second in links:
        graph.setdefault(first, []).append(second)
        graph.setdefault(second, []).append(first)
    if source not in graph or destination not in graph:
        raise NoFeasiblePath("Source or destination has no available links")

    metrics = {}
    for node, neighbours in graph.items():
        for neighbour in neighbours:
            cost = float(edge_cost(node, neighbour))
            delay = float(edge_delay(node, neighbour))
            if not all(math.isfinite(value) and value >= 0
                       for value in (cost, delay)):
                raise ValueError("Link cost and delay must be finite and nonnegative")
            metrics[(node, neighbour)] = (cost, delay)

    best = None
    best_cost = math.inf
    pending = [([source], 0.0, 0.0)]
    while pending:
        path, cost, delay = pending.pop()
        node = path[-1]
        if cost >= best_cost:
            continue
        if node == destination:
            best = (path, cost, delay)
            best_cost = cost
            continue

        for neighbour in reversed(graph[node]):
            if neighbour in path:
                continue
            added_cost, added_delay = metrics[(node, neighbour)]
            next_delay = delay + added_delay
            next_cost = cost + added_cost
            if next_delay <= delay_budget_ms and next_cost < best_cost:
                pending.append((path + [neighbour], next_cost, next_delay))

    if best is None:
        raise NoFeasiblePath("No available path meets the one-way delay budget")
    return best


def shortest_path(links, source, destination, edge_cost=None):
    """Return (node_list, total_cost) on a bidirectional logical graph.

    edge_cost(u, v) supplies a nonnegative directed cost. For the first
    algorithm check only, omitting it assigns cost 1 to every link.
    This function does not yet perform capacity admission or energy updates.
    """
    graph = {}
    for first, second in links:
        graph.setdefault(first, []).append(second)
        graph.setdefault(second, []).append(first)

    if source not in graph or destination not in graph:
        raise ValueError("Source or destination is absent from the graph")

    if edge_cost is None:
        edge_cost = lambda first, second: 1.0

    distances = {source: 0.0}
    previous = {}
    pending = [(0.0, source)]

    while pending:
        distance, node = heapq.heappop(pending)
        if distance != distances[node]:
            continue

        if node == destination:
            path = [node]
            while path[-1] != source:
                path.append(previous[path[-1]])
            path.reverse()
            return path, distance

        for neighbour in graph[node]:
            weight = float(edge_cost(node, neighbour))
            if not math.isfinite(weight) or weight < 0:
                raise ValueError("Link costs must be finite and nonnegative")

            candidate = distance + weight
            if candidate < distances.get(neighbour, math.inf):
                distances[neighbour] = candidate
                previous[neighbour] = node
                heapq.heappush(pending, (candidate, neighbour))

    raise ValueError("No path from %s to %s" % (source, destination))
