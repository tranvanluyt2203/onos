package org.onosproject.httpddosdetector.ICMP;
import com.google.common.collect.HashMultimap;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;

import static org.onosproject.net.flow.FlowRuleEvent.Type.RULE_REMOVED;
import static org.onosproject.net.flow.criteria.Criterion.Type.ETH_SRC;

public class ICMPLimit {
    private static Logger log = LoggerFactory.getLogger(ICMPLimit.class);

    private static final String MSG_PINGED_ONCE =
            "Thank you, Vasili. One ping from {} to {} received by {}";
    private static final String MSG_PINGED_TWICE =
            "What are you doing, Vasili?! I said one ping only!!! " +
                    "Ping from {} to {} has already been received by {};" +
                    " 60 second ban has been issued";
    private static final String MSG_PING_REENABLED =
            "Careful next time. Re-enabled ping from {} to {} on {}";

    private static final int PRIORITY = 128;
    private static final int DROP_PRIORITY = 129;
    private static final int TIMEOUT_SEC = 60; // seconds

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ApplicationId appId;
    private final PacketProcessor packetProcessor = new PingPacketProcessor();
    private final FlowRuleListener flowListener = new InternalFlowListener();

    // Selector for ICMP traffic that is to be intercepted
    private final TrafficSelector intercept = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4).matchIPProtocol(IPv4.PROTOCOL_ICMP)
            .build();

    // Means to track detected pings from each device on a temporary basis
    private final HashMultimap<DeviceId, PingRecord> pings = HashMultimap.create();
    private final Timer timer = new Timer("oneping-sweeper");

    // Processes the specified ICMP ping packet.
    private void processPing(PacketContext context, Ethernet eth) {
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        MacAddress src = eth.getSourceMAC();
        MacAddress dst = eth.getDestinationMAC();
        PingRecord ping = new PingRecord(src, dst);
        boolean pinged = pings.get(deviceId).contains(ping);

        if (pinged) {
            // Two pings detected; ban further pings and block packet-out
            log.warn(MSG_PINGED_TWICE, src, dst, deviceId);
            banPings(deviceId, src, dst);
            context.block();
        } else {
            // One ping detected; track it for the next minute
            log.info(MSG_PINGED_ONCE, src, dst, deviceId);
            pings.put(deviceId, ping);
            timer.schedule(new PingPruner(deviceId, ping), TIMEOUT_SEC * 1000);
        }
    }

    // Installs a temporary drop rule for the ICMP pings between given srd/dst.
    private void banPings(DeviceId deviceId, MacAddress src, MacAddress dst) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthSrc(src).matchEthDst(dst).build();
        TrafficTreatment drop = DefaultTrafficTreatment.builder()
                .drop().build();

        flowObjectiveService.forward(deviceId, DefaultForwardingObjective.builder()
                .fromApp(appId)
                .withSelector(selector)
                .withTreatment(drop)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .withPriority(DROP_PRIORITY)
                .makeTemporary(TIMEOUT_SEC)
                .add());
    }


    // Indicates whether the specified packet corresponds to ICMP ping.
    private boolean isIcmpPing(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_ICMP;
    }


    // Intercepts packets
    private class PingPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (isIcmpPing(eth)) {
                processPing(context, eth);
            }
        }
    }

    // Record of a ping between two end-station MAC addresses
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

    // Prunes the given ping record from the specified device.
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
        }
    }

    // Listens for our removed flows.
    private class InternalFlowListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            FlowRule flowRule = event.subject();
            if (event.type() == RULE_REMOVED && flowRule.appId() == appId.id()) {
                Criterion criterion = flowRule.selector().getCriterion(ETH_SRC);
                MacAddress src = ((EthCriterion) criterion).mac();
                MacAddress dst = ((EthCriterion) criterion).mac();
                log.warn(MSG_PING_REENABLED, src, dst, flowRule.deviceId());
            }
        }
    }
}
