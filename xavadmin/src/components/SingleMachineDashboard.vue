<template>
    <div class="layout">
        <el-container>
            <el-aside>
                <el-menu default-active="1">
                    <el-menu-item index="1">
                        <el-icon>
                            <Monitor />
                        </el-icon>
                        <template #title>
                            Dashboard
                        </template>
                    </el-menu-item>
                    <el-menu-item index="2">
                        <el-icon>
                            <Search />
                        </el-icon>
                        <template #title>
                            Scan
                        </template>
                    </el-menu-item>
                    <el-menu-item index="3">
                        <el-icon>
                            <View />
                        </el-icon>
                        <template #title>
                            Process Monitor
                        </template>
                    </el-menu-item>
                    <el-menu-item index="4">
                        <el-icon>
                            <Setting />
                        </el-icon>
                        <template #title>
                            Settings
                        </template>
                    </el-menu-item>
                </el-menu>
            </el-aside>
            <el-container>
                <el-header>
                    <h2>Xav Admin Management Platform</h2>
                </el-header>
                <el-main>
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
                                            <el-progress type="dashboard" :percentage="memoryUsage"
                                                :color="warningColor">
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
                    <el-row>
                        <div class="card-margin"></div>
                    </el-row>
                    <el-row>
                        <el-col :span="24">
                            <el-card>
                                <template #header>
                                    <el-icon>
                                        <Search />
                                    </el-icon>
                                    <span>&nbsp;&nbsp;Scan</span>
                                </template>
                                <template #default>
                                    <el-row>
                                        <el-button plain @click="handleQuickScanBtnClick"
                                            :disabled="scanButtonDisabled">Quick
                                            Scan</el-button>
                                        <el-button plain disabled>Full Scan</el-button>
                                        <el-button plain disabled>Custom Scan</el-button>
                                    </el-row>
                                    <div class="scan-margin"></div>
                                    <el-row>
                                        <el-col :span="24">
                                            <el-progress :percentage="scanProgress"
                                                :status="scanProgressBarStatus"></el-progress>
                                        </el-col>
                                    </el-row>
                                    <el-row>
                                        <el-col :span="24">
                                            <el-text>{{ scanStatusText }}</el-text>
                                        </el-col>
                                    </el-row>
                                    <el-row>
                                        <el-col :span="24">
                                            <el-table :data="malwareInfos" :max-height="400">
                                                <el-table-column prop="file_path" label="Path" />
                                                <el-table-column prop="malware_name" label="Malware Name">
                                                    <template #default="scope">
                                                        <el-text type="danger">{{ scope.row.malware_name }}</el-text>
                                                    </template>
                                                </el-table-column>
                                            </el-table>
                                        </el-col>
                                    </el-row>
                                    <el-row :style="{ marginTop: '15px' }">
                                        <el-col :span="20"></el-col>
                                        <el-col :span="4">
                                            <el-button type="primary" plain disabled>Quarantine</el-button>
                                            <el-button type="danger" plain disabled>Ignore</el-button>
                                        </el-col>
                                    </el-row>
                                </template>
                            </el-card>
                        </el-col>
                    </el-row>
                </el-main>
            </el-container>
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
const scanButtonDisabled = ref(false)

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

// Scan status.
const scanStatus = ref(undefined)
const scannedFileCount = ref(0)
const totalFileCount = ref(0)
const scanProgress = ref(0)
const currentScanningFile = ref("")
const malwareInfos = ref([])
const scanProgressBarStatus = computed(() => {
    if (scanStatus.value === 'Stopped') {
        return malwareInfos.value.length > 0 ? 'exception' : 'success'
    } else {
        return null
    }
})
const scanStatusText = computed(() => {
    if (scanStatus.value === 'Scanning') {
        return `Scanning file (${scannedFileCount.value} of ${totalFileCount.value}): ${currentScanningFile.value}`
    } else if (scanStatus.value === 'Stopped') {
        let ret = 'Scan completed, '
        if (malwareInfos.value.length > 0) {
            ret += 'threat detected.'
        } else {
            ret += 'no threat detected.'
        }
        return ret
    }
})

// Get scan status periodically.
const { pause, resume, isActive } = useIntervalFn(() => {
    // Get scan status agent.
    axios.get('/api/scan/quick/status')
        .then((res) => {
            const data = res.data
            scanStatus.value = data.scan_status
            if (scanStatus.value === 'Stopped') {
                scanButtonDisabled.value = false
                pause()
            }
            scannedFileCount.value = data.scanned_file_count
            totalFileCount.value = data.total_file_count
            scanProgress.value = Number((data.scanned_file_count / data.total_file_count * 100).toFixed(1))
            currentScanningFile.value = data.curr_scanning_file
            malwareInfos.value = data.malware_infos
        })
        .finally(() => {
        })
}, 500, { immediate: false })

function handleQuickScanBtnClick() {
    scanButtonDisabled.value = true
    axios.get('/api/scan/quick/start')
        .catch(() => {
            scanButtonDisabled.value = false
        })
    resume()
}
</script>