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
                        <el-button link type="primary">Behavior Chain</el-button>
                    </template>
                </el-table-column>
            </el-table>
        </template>
    </el-card>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { Search } from '@element-plus/icons-vue'

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
</script>
