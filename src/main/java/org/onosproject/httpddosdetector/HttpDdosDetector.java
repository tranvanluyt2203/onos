
package org.onosproject.httpddosdetector;

import com.google.common.collect.HashMultimap;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.httpddosdetector.classifier.Classifier;
import org.onosproject.httpddosdetector.classifier.randomforest.RandomForestBinClassifier;
import org.onosproject.httpddosdetector.flow.parser.FlowData;
import org.onosproject.httpddosdetector.keys.FlowKey;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.*;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;



@Component(immediate = true)
public class HttpDdosDetector {

    private static Logger log = LoggerFactory.getLogger(HttpDdosDetector.class);

    private static final int PROCESSOR_PRIORITY = 128;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ApplicationId appId;
    private final PacketProcessor packetProcessor = new TCPPacketProcessor();

    // Selector for TCP traffic that is to be intercepted
    private final TrafficSelector intercept = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4).matchIPProtocol(IPv4.PROTOCOL_TCP)
            .build();

    // Holds the current active flows
    private HashMap<FlowKey, FlowData> flows = new HashMap<FlowKey, FlowData>();

    private Classifier classifier;
    private final HashMultimap<DeviceId, PingRecord> pings = HashMultimap.create();
    private final Timer timer = new Timer("oneping-sweeper");
    /**
     * Runs when the application is started, after activation or reinstall
     */
    @Activate
    protected void activate() {
        appId = coreService.registerApplication("mx.itesm.IDPS", () -> log.info("IDPS Active."));

        packetService.addProcessor(packetProcessor, PROCESSOR_PRIORITY);
        packetService.requestPackets(intercept, PacketPriority.CONTROL, appId,
                                     Optional.empty());

        classifier = new RandomForestBinClassifier();
        classifier.Load("/models/random_forest_bin.json");

        log.info("IDPS started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flowRuleService.removeFlowRulesById(appId);
        flows.clear();
        log.info("IDPS stopped");
    }
    private void processPacket(PacketContext context, Ethernet eth) {
        // Get identifiers of the packet
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        IPv4 ipv4 = (IPv4) eth.getPayload();
        int srcip = ipv4.getSourceAddress();
        int dstip = ipv4.getDestinationAddress();
        byte proto = ipv4.getProtocol();
        PingRecord ping = new PingRecord(eth.getSourceMAC(), eth.getDestinationMAC());

        TCP tcp = (TCP) ipv4.getPayload();
        int srcport = tcp.getSourcePort();
        int dstport = tcp.getDestinationPort();
        boolean pinged = pings.get(deviceId).contains(ping);
        if(pinged){
            context.block();
        }
        else {
        FlowKey forwardKey = new FlowKey(srcip, srcport, dstip, dstport, proto);
        FlowKey backwardKey = new FlowKey(dstip, dstport, srcip, srcport, proto);
        FlowData f;

        if(flows.containsKey(forwardKey) || flows.containsKey(backwardKey)){
            // Get corresponding flow and update it
            if(flows.containsKey(forwardKey)){
                f = flows.get(forwardKey);
            }else{
                f = flows.get(backwardKey);
            }
            f.Add(eth, srcip);

            f.Export();
     } else {
            f = new FlowData(srcip, srcport, dstip, dstport, proto, eth);

            flows.put(forwardKey, f);
            flows.put(backwardKey, f);
        }


        // If connection is closed
        try {
            if(f != null && f.IsClosed()){
                RandomForestBinClassifier.Class flowClass= RandomForestBinClassifier.Class.valueOf(classifier.Classify(f));

                switch(flowClass){
                    case NORMAL:
                        log.info("Detected normal flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                        break;
                    case ATTACK:
                        timer.schedule(new PingPruner(deviceId, ping), 60 * 1000);
                        pings.put(deviceId, ping);
                        log.warn("Detected attack flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                        break;
                    case ERROR:
                        log.error("Error predicting flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                        break;
                }
                // Delete from flows, since it is closed we don't expect any other packet from this flow
                flows.remove(forwardKey);
                flows.remove(backwardKey);
                f = null;
            }

        }catch (Exception e){
            log.warn("");
        }

    }}
    private class PingRecord {
        private final MacAddress src;
        private final MacAddress dst;

        PingRecord(MacAddress src, MacAddress dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            final PingRecord other = (PingRecord) obj;
            return Objects.equals(this.src, other.src) && Objects.equals(this.dst, other.dst);
        }
    }
    private static final int TIMEOUT_SEC = 10;
    private class PingPruner extends TimerTask {
        private final DeviceId deviceId;
        private final PingRecord ping;

        public PingPruner(DeviceId deviceId, PingRecord ping) {
            this.deviceId = deviceId;
            this.ping = ping;
        }

        @Override
        public void run() {
            pings.remove(deviceId, ping);
            log.info("Re-enabled connect from {} to {}", ping.src, ping.src);
        }
    }
    private static final String MSG_PINGED_TWICE =
                    "Ping from {} to {} ;";
    private void processPing(PacketContext context, Ethernet eth) {
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        MacAddress src = eth.getSourceMAC();
        MacAddress dst = eth.getDestinationMAC();
        PingRecord ping = new PingRecord(src, dst);
        boolean pinged = pings.get(deviceId).contains(ping);

        if (pinged) {
            context.block();
        } else {
            log.info(MSG_PINGED_TWICE, src, dst, deviceId);
            pings.put(deviceId, ping);
            timer.schedule(new PingPruner(deviceId, ping), TIMEOUT_SEC * 1000);
        }
    }

    private boolean isTcpPacket(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP;
    }

    private boolean isIcmpPing(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_ICMP;
    }

    private class TCPPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet packet = context.inPacket().parsed();
            
            if (packet == null) {
                return;
            }

            if(isIcmpPing(packet)){
                processPing(context, packet);
            }
            if (isTcpPacket(packet)) {
                processPacket(context, packet);
            }
        }
    }

}
