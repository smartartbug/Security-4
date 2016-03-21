package scannerfinder;

import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.Ip4;
import java.util.*;
import org.jnetpcap.packet.format.FormatUtils;

/**
 *
 * @author Genevieve Suwara, Kevin Ripley
 */
public class Scannerfinder {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        //get file from arguments
        final String file = "C:\\Users\\smart_000\\Desktop\\test.pcap";//args[0];
        final StringBuilder errbuf = new StringBuilder();
        
        //open the pcap file
        final Pcap pcap = Pcap.openOffline(file, errbuf);
        //print error if pcap is null
        if (pcap == null){
            System.err.println(errbuf);
        }
        
        //create maps for the two categories of IP addresses we want to track
        final Map<String, Integer> synSenders = new HashMap<>();
        final Map<String, Integer> synAckReceivers = new HashMap<>();
            
        //loop through the pcap file until it there are no more packets to read
        pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {
            //create storage for headers
            final Ip4 ip = new Ip4();
            final Tcp tcp = new Tcp();
            
            //get the next packet
            @Override
            public void nextPacket(JPacket packet, StringBuilder errbuf){
                //if headers are available...
                if(packet.hasHeader(Ip4.ID) && packet.hasHeader(Tcp.ID)){
                    //put them in our header storage
                    packet.getHeader(ip);
                    packet.getHeader(tcp);
                    
                    //if the packet is sending SYN...
                    if(tcp.flags_SYN())
                    {
                        //if the packet is not sending ACK...
                        if(!tcp.flags_ACK())
                        {
                            //if the sender IP has not been put in the map yet...
                            if (!synSenders.containsKey(FormatUtils.ip(ip.source())))
                            {
                                //put the IP in the map and record their 1 SYN packet sent
                                synSenders.put(FormatUtils.ip(ip.source()), 1);
                            }
                            else 
                            {
                                //increment the number of SYN packets associated with that IP
                                synSenders.put(FormatUtils.ip(ip.source()), synSenders.get(FormatUtils.ip(ip.source())) + 1);
                            }
                        }
                        //otherwise, if the packet IS sending ACK...
                        else 
                        {
                            //if the destination IP has not been put int the map yet...
                            if (!synAckReceivers.containsKey(FormatUtils.ip(ip.destination())))
                            {
                                //put the IP in the map and record their 1  SYN+ACK packet received
                                synAckReceivers.put(FormatUtils.ip(ip.destination()), 1);
                            }
                            else 
                            {
                                //increment the number of SYN+ACK packets associated with that IP
                                synAckReceivers.put(FormatUtils.ip(ip.destination()), synAckReceivers.get(FormatUtils.ip(ip.destination())) + 1);
                            }
                        }
                    }
                }
            }
        }, errbuf);
        
        //for each IP in the map of SYN packet senders...
        for (Map.Entry<String, Integer> entry : synSenders.entrySet())
        {
            //if that IP also appears in the map of SYN+ACK packet receivers...
            if (synAckReceivers.get(entry.getKey()) != null)
            {
                //if that IP sent more than 3 times as many SYN packets as SYN+ACK packets it received...
                if (entry.getValue() > (3 * synAckReceivers.get(entry.getKey()))){
                    //print that IP
                    System.out.println(entry.getKey());
                }
            }
            //otherwise, if that IP doesn't also appear in the map of SYN+ACK packet receivers
            //print that IP (since it only sent SYN packets and didn't receive any SYN+ACK packets)
            else System.out.println(entry.getKey());
        }
    }
    
}
