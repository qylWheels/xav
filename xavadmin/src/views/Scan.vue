<template>
    <el-card>
        <template #header>
            <el-icon>
                <Search />
            </el-icon>
            <span>&nbsp;&nbsp;Scan</span>
        </template>
        <template #default>
            <el-row>
                <el-button plain @click="handleQuickScanBtnClick" :disabled="scanButtonDisabled">Quick
                    Scan</el-button>
                <el-button plain disabled>Full Scan</el-button>
                <el-button plain disabled>Custom Scan</el-button>
            </el-row>
            <el-divider></el-divider>
            <el-row>
                <el-col :span="24">
                    <el-progress :percentage="scanProgress" :status="scanProgressBarStatus"></el-progress>
                </el-col>
            </el-row>
            <el-row>
                <el-col :span="24">
                    <el-text truncated>{{ scanStatusText }}</el-text>
                </el-col>
            </el-row>
            <el-row>
                <el-col :span="24">
                    <el-table :data="malwareInfos" :height="335">
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
                <el-col :span="19"></el-col>
                <el-col :span="5">
                    <el-button type="primary" plain disabled>Quarantine</el-button>
                    <el-button type="danger" plain disabled>Ignore</el-button>
                </el-col>
            </el-row>
        </template>
    </el-card>
</template>

<style scoped></style>

<script setup lang="ts">
import axios from 'axios'
import { ref, computed } from 'vue'
import { useIntervalFn, useCssVar } from '@vueuse/core'

// Scan status.
const scanButtonDisabled = ref(false)
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
