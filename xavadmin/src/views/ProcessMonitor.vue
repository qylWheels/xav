<template>
    <el-card>
        <template #header>
            <el-icon>
                <View />
            </el-icon>
            <span>
                &nbsp;&nbsp;Process Monitor
            </span>
        </template>
        <template #default>
            <el-input v-model="searchText" placeholder="Search process via PID, path, cmdline" :prefix-icon="Search" />
            <el-table :data="procs" height="480">
                <el-table-column prop="pid" label="PID" width="100" sortable />
                <el-table-column prop="path" label="Path" width="250" sortable />
                <el-table-column prop="cmdline" label="Command Line" width="450" sortable />
                <el-table-column prop="ppid" label="PPID" width="100" sortable />
                <el-table-column>
                    <template #default="scope">
                        <el-button link type="primary" @click="onClickShowBehaviorChainBtn(scope.row)">Behavior
                            Chain</el-button>
                    </template>
                </el-table-column>
            </el-table>
        </template>
    </el-card>
    <el-dialog v-model="showBehaviorChain" :title="title" @close="onCloseBehaviorChainDialogClose" width="95%"
        :align-center="true">
        <el-row>
            <el-text>Filter By Severity&nbsp;&nbsp;</el-text>
            <el-radio-group v-model="filterBySeverity">
                <el-radio-button label="Info" value="Info" />
                <el-radio-button label="Warning" value="Warning" />
                <el-radio-button label="Danger" value="Danger" />
            </el-radio-group>
        </el-row>
        <div style="height: 20px;"></div>
        <el-timeline>
            <el-timeline-item center v-for="(activity, index) in activities" :key="index"
                :timestamp="activity.timestamp" :color="activity.color" placement="top">
                <el-card>
                    <template #header>
                        {{ activity.content }}
                    </template>
                    <el-text>{{ activity.details }}</el-text>
                </el-card>
            </el-timeline-item>
        </el-timeline>
    </el-dialog>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { Search, Warning } from '@element-plus/icons-vue'
import { infoColor, warningColor, dangerColor } from '@/utils/colors'

const activities = [
    {
        content: 'Call process_vm_writev to inject other process',
        timestamp: '2018-04-15 10:00:00',
        details: 'process_vm_writev(227222, 0x7f9000000000, 0x1000000, 0x1000000) = 34',
        color: warningColor.value,
    },
    {
        content: 'Call mprotect to modify memory protection to executable',
        timestamp: '2018-04-13 10:00:01',
        details: 'mprotect(227222, 0x7f9000000000, 0x1000000, 0x1000000, 0x1000000) = 0',
        color: warningColor.value,
    },
    {
        content: 'Call execve to execute the injected code',
        timestamp: '2018-04-11 10:00:03',
        details: 'execve(227222, ["/bin/bash"], {"/bin/bash": "/bin/bash"}) = 0(success)',
        color: dangerColor.value,
    },
]

const searchText = ref('')

const procs = ref([
    {
        pid: 227222,
        path: '/bin/bash',
        cmdline: 'bash -c ls',
        ppid: 132,
    },
    {
        pid: 132,
        path: '/bin/sudo',
        cmdline: 'sudo bash',
        ppid: 0,
    }
])

// Behavior chain dialog.
const showBehaviorChain = ref(false)
const title = ref('')
const filterBySeverity = ref('New York')
function onClickShowBehaviorChainBtn(row: any) {
    showBehaviorChain.value = true
    title.value = `Behavior Chain of PID ${row.pid}`
}
function onCloseBehaviorChainDialogClose() {
    showBehaviorChain.value = false
}
</script>