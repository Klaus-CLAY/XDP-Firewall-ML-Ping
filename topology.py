import comnetsemu.tool as tool
from comnetsemu.net import Containernet
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.node import Controller
from comnetsemu.cli import CLI, spawnXtermDocker


def testTopo():
    net = Containernet(controller=Controller, link=TCLink)

    info("*** Adding controller\n")
    net.addController("c0")

    info("*** Adding hosts\n")
    center = net.addDockerHost(
        "center",
        dimage="ebpf-fw",
        ip="10.0.0.1",
        docker_args={"cpuset_cpus": "1", "cpu_quota": 25000, "hostname": "center"},
    )
    client1 = net.addDockerHost(
        "client1",
        dimage="ebpf-fw",
        ip="10.0.0.2",
        docker_args={"cpuset_cpus": "1", "cpu_quota": 25000, "hostname": "client1"},
    )
    client2 = net.addDockerHost(
        "client2",
        dimage="ebpf-fw",
        ip="10.0.0.3",
        docker_args={"cpuset_cpus": "1", "cpu_quota": 25000, "hostname": "client2"},
    )

    info("*** Adding switch\n")
    s1 = net.addSwitch("s1")

    info("*** Creating links\n")
    net.addLinkNamedIfce(s1, center, bw=10, delay="10ms")
    net.addLinkNamedIfce(s1, client1, bw=10, delay="10ms")
    net.addLinkNamedIfce(s1, client2, bw=10, delay="10ms")

    info("*** Starting network\n")
    net.start()
    spawnXtermDocker("center")
    spawnXtermDocker("client1")
    CLI(net)

    # info("*** Create wg key pairs\n")
    # center_private_key = center.cmd("cat ./privatekey")

    # center.cmd(
    #     "printf -- '[Interface]\nAddress = 192.168.0.1/24\nSaveConfig = true\nListenPort = 1337\nPrivateKey = "
    #     + center_private_key + " > /etc/wireguard/wg0.conf"
    # )

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    testTopo()
