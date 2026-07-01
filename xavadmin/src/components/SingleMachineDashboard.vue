<template>
    <div class="layout">
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
                                        <el-icon class="monitor-icon" size="128" :color="color">
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
                                        <el-button type="danger" plain>Disconnect</el-button>
                                    </el-col>
                                    <el-col :span="4">
                                        <el-statistic title="Real-time Protection Scanned Files"
                                            :value="realTimeProtScanFiles" />
                                        <div class="statistic-margin" />
                                        <el-statistic title="Malware Blocked" :value="malwareBlockedCount" />
                                    </el-col>
                                    <el-col :span="3">
                                        <el-statistic title="Analyzed Behaviors" :value="analyzedBehaviorsCount" />
                                        <div class="statistic-margin" />
                                        <el-statistic title="Suspicious Behaviors" :value="suspiciousBehaviorCount" />
                                    </el-col>
                                    <el-col :span="3">
                                        <el-progress type="dashboard" :percentage="cpuUsage" :color="color">
                                            <template #default="{ percentage }">
                                                <el-text class="percentage-value">{{ percentage }}%</el-text>
                                                <el-text class="percentage-label">CPU Usage</el-text>
                                            </template>
                                        </el-progress>
                                    </el-col>
                                    <el-col :span="3">
                                        <el-progress type="dashboard" :percentage="memoryUsage" :color="color">
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
                    <el-col :span="8">
                        <el-card>
                            <template #header>
                                <el-icon>
                                    <Search />
                                </el-icon>
                                <span>&nbsp;&nbsp;Scan</span>
                            </template>
                            <template #default>
                                <el-row>
                                    <el-button type="primary" plain @click="handleQuickScanBtnClick">Quick
                                        Scan</el-button>
                                    <el-button type="primary" plain>Full Scan</el-button>
                                    <el-button type="primary" plain>Custom Scan</el-button>
                                </el-row>
                                <div class="scan-margin"></div>
                                <el-row>
                                    <el-col :span="24">
                                        <el-progress :percentage="scanProgress"></el-progress>
                                    </el-col>
                                </el-row>
                                <el-row>
                                    <el-col :span="24">
                                        <el-text>Scanning file: </el-text>
                                    </el-col>
                                </el-row>
                                <el-row>
                                    <el-col :span="24">
                                        <el-text truncated>{{ currentScanningFile }}</el-text>
                                    </el-col>
                                </el-row>
                                <el-row>
                                    <el-col :span="24">
                                        <el-table :data="scanResult" :max-height="300">
                                            <el-table-column prop="path" label="Path" />
                                            <el-table-column prop="threatType" label="Threat Type">
                                                <template #default="scope">
                                                    <el-text type="danger">{{ scope.row.threatType }}</el-text>
                                                </template>
                                            </el-table-column>
                                        </el-table>
                                    </el-col>
                                </el-row>
                                <el-row :style="{ marginTop: '15px' }">
                                    <el-col :span="12"></el-col>
                                    <el-col :span="12">
                                        <el-button type="primary" plain>Quarantine</el-button>
                                        <el-button type="danger" plain>Ignore</el-button>
                                    </el-col>
                                </el-row>
                            </template>
                        </el-card>
                    </el-col>
                </el-row>
            </el-main>
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
import { ref } from 'vue'

const machineName = ref("Comma")
const color = ref("green")
const system = ref("Linux")
const realTimeProtScanFiles = ref(32917)
const malwareBlockedCount = ref(21)
const analyzedBehaviorsCount = ref(1743)
const suspiciousBehaviorCount = ref(15)
const cpuUsage = ref(80)
const memoryUsage = ref(60)
const scanProgress = ref(72)
const currentScanningFile = ref("/home/comma/projs/xav/xavadmin/src/components/SingleMachineDashboard.vue")
const scanResult = ref([
    {
        path: "/home/comma/projs/xav/xavadmin/src/components/SingleMachineDashboard.vue",
        threatType: "Ransom.wannacry.a"
    },
    {
        path: "/home/comma/projs/xav/xavadmin/a.txt",
        threatType: "Exploit.CVE-020-0688.g"
    },
    {
        path: "/home/comma/projs/xav/xavadmin/src/components/SingleMachineDashboard.vue",
        threatType: "Suspicious Behavior"
    },
    {
        path: "/home/comma/projs/xav/xavadmin/src/components/SingleMachineDashboard.vue",
        threatType: "Suspicious Behavior"
    }
])

function handleQuickScanBtnClick() {
    axios.get('/api/scan/quick')
        .then(() => {

        }).finally(() => {

        })
}
</script>