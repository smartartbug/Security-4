package scannerfinder;

import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.Ip4;
import java.util.*;

/**
 *
 * @author Genevieve Suwara, Kevin Ripley
 */
public class Scannerfinder {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        final String file = "C:/Users/smart_000/Desktop/test.pcap";//args[0];
        final StringBuilder errbuf = new StringBuilder();
        
        final Pcap pcap = Pcap.openOffline(file, errbuf);
        if (pcap == null){
            System.err.println(errbuf);
        }
        
        final Map<Integer, Integer> all = new HashMap<>();
        final Map<Integer, Integer> unsuspicious = new HashMap<>();
            
        //I figured out that I need to use the IP address and tcp info to do 
        //this, so I will work on it more tomorrow.
        pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {
            final Ip4 ip = new Ip4();
            final Tcp tcp = new Tcp();
            final Http http = new Http();
            
            @Override
            public void nextPacket(JPacket packet, StringBuilder errbuf){
                if(packet.hasHeader(Tcp.ID)){
                    packet.getHeader(tcp);
                    
                    if (all.get(tcp.source()) == null)
                    {
                        all.put(tcp.source(), 1);
                    }
                    else 
                    {
                        all.put(tcp.source(), all.get(tcp.source()) + 1);
                    }

                    if (tcp.ack() != 0)
                    {
                        if (unsuspicious.get(tcp.source()) == null)
                        {
                            unsuspicious.put(tcp.source(), 1);
                        }
                        else
                        {
                            unsuspicious.put(tcp.source(), unsuspicious.get(tcp.source()) + 1);
                        }
                    }
//                    System.out.printf("tcp.dst_port=%d%n", tcp.destination());
//                    System.out.printf("tcp.src_port=%d%n", tcp.source());
//                    if (tcp.flags_ACK()){
//                        System.out.printf("tcp.ack=%x%n", tcp.ack());
//                    }
//                    else System.out.printf("    tcp.ack=%x%n", tcp.ack());
                }
            }
        }, errbuf);
        
        for (Map.Entry<Integer, Integer> entry : all.entrySet())
        {
            if (unsuspicious.get(entry.getKey()) != null)
            {
                if (entry.getValue() > (3 * unsuspicious.get(entry.getKey()))){
                    System.out.println(entry.getKey());
                }
            }
            else System.out.println(entry.getKey());
        }
            
    }
    
}
