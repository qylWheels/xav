<template>
    <div class="layout">
        <el-container>
            <el-row>
                <el-col :span="24">
                    <el-card>
                        <template #header>
                            <el-icon>
                                <Monitor />
                            </el-icon>
                            <span>&nbsp;&nbsp;Basic Information of {{ machineName }}</span>
                        </template>
                        <template #default>
                            <el-row>
                                <el-col :span="2"></el-col>
                                <el-col :span="2">
                                    <el-icon class="monitor-icon" size="128" :color="successColor">
                                        <Monitor />
                                    </el-icon>
                                </el-col>
                                <el-col :span="1"></el-col>
                                <el-col :span="5">
                                    <el-row class="basic-info">
                                        <el-text>System: {{ system }}</el-text>
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
                                <el-col :span="4">
                                    <el-statistic title="On Access Scanner Scanned Objects"
                                        :value="onAccessScannerScanObjectCount" />
                                    <div class="statistic-margin" />
                                    <el-statistic title="On Access Scanner Blocked Threats"
                                        :value="onAccessScannerBlockedThreatsCount"
                                        :value-style="{ color: dangerColor }" />
                                </el-col>
                                <el-col :span="3">
                                    <el-statistic title="Total Events" :value="totalEventCount" />
                                    <div class="statistic-margin" />
                                    <el-statistic title="Suspicious Events" :value="suspiciousEventCount"
                                        :value-style="{ color: warningColor }" />
                                </el-col>
                                <el-col :span="3">
                                    <el-progress type="dashboard" :percentage="cpuUsage" :color="dangerColor">
                                        <template #default="{ percentage }">
                                            <el-text class="percentage-value">{{ percentage }}%</el-text>
                                            <el-text class="percentage-label">CPU Usage</el-text>
                                        </template>
                                    </el-progress>
                                </el-col>
                                <el-col :span="3">
                                    <el-progress type="dashboard" :percentage="memoryUsage" :color="warningColor">
                                        <template #default="{ percentage }">
                                            <el-text class="percentage-value">{{ percentage }}%</el-text>
                                            <el-text class="percentage-label">Memory Usage</el-text>
                                        </template>
                                    </el-progress>
                                </el-col>
                            </el-row>
                        </template>
                    </el-card>
                </el-col>
            </el-row>
        </el-container>
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
const totalEventCount = ref(0)
const suspiciousEventCount = ref(0)
const {
    pause: pauseQueryBehaviorMonitorStatus,
    resume: resumeQueryBehaviorMonitorStatus,
    isActive: isQueryBehaviorMonitorStatusActive
} = useIntervalFn(() => {
    axios.get('/api/behavior-monitor/status')
        .then((res) => {
            const data = res.data
            totalEventCount.value = data.total_event_count
            suspiciousEventCount.value = data.suspicious_event_count
        })
}, 3000, { immediate: true })
</script>
