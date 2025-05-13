import <filesystem>;
import <iostream>;
import <format>;
#include "Packet.h"

int main(int argc, char* argv[])
{
    const std::string tsharkPath = "\"C:\\Program Files\\Wireshark\\tshark.exe\"";
    const std::string filePath   = "resource\\capture.pcap";
    const std::string argFile    = "-r " + filePath;

    const std::string argDisplay1 =
        "-T fields -e frame.number -e frame.time -e frame.cap_len -e ip.src -e ipv6.src";
    const std::string argDisplay2 =
        " -e tcp.srcport -e udp.srcport -e ip.dst -e ipv6.dst";
    const std::string argDisplay3 =
        " -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info";

    const std::string argDisplay = argDisplay1 + argDisplay2 + argDisplay3;
    const std::string command    = "\"" + tsharkPath + " " + argFile + " " + argDisplay + "\"";
    std::cout << "Command: " << command << std::endl;
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe)
    {
        std::cerr << "Failed to open pipe." << std::endl;
        return 1;
    }

    std::vector<Packet> packets;
    char                buffer[4096];

    uint32_t fileOffset = sizeof(PcapHeader); // point to the first packet
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        Packet packet;
        ParseLine(buffer, packet);
        packet.FileOffset = fileOffset + sizeof(PacketHeader); // point to the first packet data
        fileOffset += packet.CapLen + sizeof(PacketHeader);    // point to the next packet (skip header)
        packets.push_back(packet);
    }

    for (auto& p : packets)
    {
        PrintPacket(p);

        if (std::vector<unsigned char> b; ReadPacketHex(filePath, p.FileOffset, p.CapLen, b))
        {
            std::cout << "Packet Hex: ";
            for (const auto& byte : b)
            {
                std::cout << std::format("{:02X} ", byte);
            }
            std::cout << std::endl;
        }
        else
        {
            std::cerr << "Failed to read packet data." << std::endl;
        }
        std::cout << std::endl;
    }

    if (_pclose(pipe) == -1)
    {
        std::cerr << "Failed to close pipe." << std::endl;
        return 1;
    }
    return 0;
}
