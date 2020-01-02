package bifrost.consensus.ouroboros;

import com.sun.management.OperatingSystemMXBean;

import java.lang.management.ManagementFactory;

public class SystemLoadMonitor {
    OperatingSystemMXBean bean = (OperatingSystemMXBean) ManagementFactory
            .getOperatingSystemMXBean();
    double cpuLoad() {
        double value = bean.getSystemCpuLoad();
        return value;
    }
}
