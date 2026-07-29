<template>
    <el-card shadow="hover">
        <template #header>
            <div>Overview</div>
        </template>
        <el-row>
            <el-col :span="1"></el-col>
            <el-col :span="3">
                <el-statistic class="devices-at-risk" title="Device(s) At Risk" :value="devicesAtRisk">
                    <template #suffix>/{{ totalDeviceCount }}</template>
                </el-statistic>
            </el-col>
            <el-col :span="1"></el-col>
            <el-col :span="3">
                <el-statistic title="Online Device Count" :value="onlineDeviceCount">
                    <template #suffix>/{{ totalDeviceCount }}</template>
                </el-statistic>
            </el-col>
            <el-col :span="1"></el-col>
            <el-col :span="3">
                <VueUiSparkline :dataset="deviceDataset" :config="deviceConfig"></VueUiSparkline>
            </el-col>
        </el-row>
        <el-divider />
        <el-row>
            <el-col :span="1"></el-col>
            <el-col :span="3">
                <el-statistic class="severe-event-count" title="Severe Event Count" :value="severeEventCount">
                </el-statistic>
            </el-col>
            <el-col :span="1"></el-col>
            <el-col :span="3">
                <el-statistic class="suspicious-event-count" title="Suspicious Event Count"
                    :value="suspiciousEventCount">
                </el-statistic>
            </el-col>
            <el-col :span="1"></el-col>
            <el-col :span="3">
                <el-statistic class="total-event-count" title="Total Event Count" :value="totalEventCount">
                </el-statistic>
            </el-col>
            <el-col :span="1"></el-col>
            <el-col :span="3">

            </el-col>
        </el-row>
    </el-card>
</template>

<style lang="scss" scoped>
.severe-event-count :deep(.el-statistic__content) {
    color: var(--el-color-danger);
}

.suspicious-event-count :deep(.el-statistic__content) {
    color: var(--el-color-warning);
}

.total-event-count :deep(.el-statistic__content) {
    color: var(--el-color-info);
}

.devices-at-risk :deep(.el-statistic__content) {
    color: var(--el-color-danger);
}
</style>

<script setup lang="ts">
import { ref } from "vue";
import { useCssVar } from '@vueuse/core'
import {
    VueUiSparkline,
    type VueUiSparklineDatasetItem,
    type VueUiSparklineConfig
} from "vue-data-ui/vue-ui-sparkline";

// Colors.
const primaryColor = useCssVar('--el-color-primary')

const devicesAtRisk = ref(3);
const onlineDeviceCount = ref(36);
const deviceDataset = ref<VueUiSparklineDatasetItem[]>([
    {
        "period": "period 1",
        "value": 0
    },
    {
        "period": "period 2",
        "value": -1
    },
    {
        "period": "period 3",
        "value": 2
    },
    {
        "period": "period 4",
        "value": -3
    },
    {
        "period": "period 5",
        "value": 4
    },
    {
        "period": "period 6",
        "value": -5
    },
]);
const deviceConfig = ref<VueUiSparklineConfig>({
    style: {
        line: { smooth: true },
        area: {
            color: primaryColor.value?.toString(),
        }
    }
});

const totalDeviceCount = ref(52);
const severeEventCount = ref(10);
const suspiciousEventCount = ref(125);
const totalEventCount = ref(376221);

</script>
