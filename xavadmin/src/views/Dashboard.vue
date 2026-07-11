<template>
    <div class="layout">
        <el-card>
            <template #header>
                <el-icon>
                    <PieChart />
                </el-icon>
                <span>&nbsp;&nbsp;Dashboard</span>
            </template>
            <template #default>
                <el-row>
                    <el-col :span="1"></el-col>
                    <el-col :span="4">
                        <el-icon class="monitor-icon" size="128" :color="successColor">
                            <Monitor />
                        </el-icon>
                    </el-col>
                    <el-col :span="6">
                        <el-row class="basic-info">
                            <el-text>Name: {{ machineName }}</el-text>
                        </el-row>
                        <el-row class="basic-info">
                            <el-text>Connection Status: </el-text>
                            <el-tag type="success" class="basic-info-tag">Online</el-tag>
                        </el-row>
                        <el-row class="basic-info">
                            <el-text>Security Status: </el-text>
                            <el-tag type="success" class="basic-info-tag">Safe</el-tag>
                        </el-row>
                        <el-button type="danger" plain disabled>Disconnect</el-button>
                    </el-col>
                    <el-col :span="6">
                        <el-statistic title="On Access Scanner Scanned Object(s)"
                            :value="onAccessScannerScanObjectCount" />
                        <div class="statistic-margin" />
                        <el-statistic title="On Access Scanner Blocked Threat(s)"
                            :value="onAccessScannerBlockedThreatsCount" :value-style="{ color: dangerColor }" />
                    </el-col>
                    <el-col :span="3">
                        <el-statistic title="Behavior(s) Detected" :value="totalBehavCount" />
                        <div class="statistic-margin" />
                        <el-statistic title="Suspicious Behavior(s)" :value="suspiciousBehavCount"
                            :value-style="{ color: warningColor }" />
                    </el-col>
                </el-row>
                <el-row>
                    <el-divider></el-divider>
                </el-row>
                <el-row>
                    <el-text type="large" tag="b">Recent Security Event(s)</el-text>
                </el-row>
                <el-row>
                    <el-table :data="recentSecurityEvents" height="310">
                        <el-table-column prop="time" label="Time" width="180" />
                        <el-table-column prop="category" label="Category" width="180" />
                        <el-table-column prop="severity" label="Severity" width="100">
                            <template #default="scope">
                                <el-tag :type="severityOfEvent(scope.row)">{{ scope.row.severity }}</el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column prop="desc" label="Description" />
                    </el-table>
                </el-row>
            </template>
        </el-card>
    </div>
</template>

<style scoped>
.basic-info {
    margin-bottom: 10px;
}

.basic-info-tag {
    margin-left: 5px;
}

.statistic-margin {
    height: 15px;
}

.scan-margin {
    height: 15px;
}

.card-margin {
    height: 15px;
}

.percentage-value {
    display: block;
    margin-top: 10px;
    font-size: 24px;
}

.percentage-label {
    display: block;
    margin-top: 10px;
    font-size: 12px;
}
</style>

<script setup lang="ts">
import axios from 'axios'
import { ref, computed } from 'vue'
import { useIntervalFn, useCssVar } from '@vueuse/core'

// Colors.
const primaryColor = useCssVar('--el-color-primary')
const successColor = useCssVar('--el-color-success')
const warningColor = useCssVar('--el-color-warning')
const infoColor = useCssVar('--el-color-info')
const dangerColor = useCssVar('--el-color-danger')

const machineName = ref("Comma")
const color = ref("green")
const system = ref("Linux")
const cpuUsage = ref(80)
const memoryUsage = ref(60)

const recentSecurityEvents = ref([
    {
        time: '2016-05-03 10:00:00',
        category: 'Suspicious Behavior',
        severity: 'Medium',
        desc: '/bin/bash tries to inject malicious code into /sbin/systemd',
    },
    {
        time: '2016-05-03 10:00:02',
        category: 'Malware Blocked',
        severity: 'High',
        desc: 'On access scanner blocked /bin/bash2, because it is Ransom.Petya.d',
    }
])
recentSecurityEvents.value = recentSecurityEvents.value.flatMap((item) => [item, item, item, item, item, item])

const severityOfEvent = (event: any) => {
    if (event.severity === 'Medium') {
        return 'warning'
    } else if (event.severity === 'High') {
        return 'danger'
    } else if (event.severity === 'Low') {
        return 'info'
    }
    return 'primary'
}

// Real-time protection status.
const onAccessScannerScanObjectCount = ref(0)
const onAccessScannerBlockedThreatsCount = ref(0)
const {
    pause: pauseQueryRealTimeProtectionStatus,
    resume: resumeQueryRealTimeProtectionStatus,
    isActive: isQueryRealTimeProtectionStatusActive
} = useIntervalFn(() => {
    axios.get('/api/on-access-scanner/status')
        .then((res) => {
            const data = res.data
            onAccessScannerScanObjectCount.value = data.scanned_object_count
            onAccessScannerBlockedThreatsCount.value = data.blocked_object_count
        })
}, 3000, { immediate: true })

// Behavior monitor status.
const totalBehavCount = ref(0)
const suspiciousBehavCount = ref(0)
const {
    pause: pauseQueryBehaviorMonitorStatus,
    resume: resumeQueryBehaviorMonitorStatus,
    isActive: isQueryBehaviorMonitorStatusActive
} = useIntervalFn(() => {
    axios.get('/api/behavior-monitor/status')
        .then((res) => {
            const data = res.data
            totalBehavCount.value = data.total_event_count
            suspiciousBehavCount.value = data.suspicious_event_count
        })
}, 3000, { immediate: true })
</script>
