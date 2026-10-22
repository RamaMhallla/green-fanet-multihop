# OpenFlow switch
SWITCH_NAME = "s1"
SWITCH_DPID = 1

# Ryu controller
CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653

# Existing Docker image
DOCKER_IMAGE = "fanet-node:latest"

# UAV containers
DRONES = ["UAV1", "UAV2", "UAV3","UAV4"]

# Fixed path for the first test
TEST_PATH = ["UAV2", "UAV4"]

# End hosts: IP address and MAC address
HOSTS = {
    "u1": ("10.0.0.1/24", "00:00:00:00:00:01"),
    "gs": ("10.0.0.100/24", "00:00:00:00:00:64"),
}

# Per-UAV egress limits, independently in each direction
UAV_BW_MBPS = 5

# Delay applied once per UAV traversal, in each direction
UAV_DELAY_MS = 10
def port_map():
    ports = {
        "u1": 1,
        "gs": 2,
    }

    next_port = 3

    for drone in DRONES:
        ports[(drone, "IN")] = next_port
        ports[(drone, "OUT")] = next_port + 1

        next_port += 2

    return ports

# Allowed logical links; each link is bidirectional.
LOGICAL_LINKS = [
    ("u1", "UAV1"),
    ("u1", "UAV2"),
    ("UAV1", "UAV3"),
    ("UAV1", "UAV4"),
    ("UAV2", "UAV3"),
    ("UAV2", "UAV4"),
    ("UAV3", "gs"),
    ("UAV4", "gs"),
]