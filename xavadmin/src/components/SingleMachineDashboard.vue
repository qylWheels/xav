<template>
    <div class="layout">
        <el-container>
            <el-header>
                <h2>Xav Admin Management Console</h2>
            </el-header>
            <el-main>
                <el-card>
                    <template #header>
                        <span>Basic Information of {{ machineName }}</span>
                    </template>
                    <template #default>
                        <i class="fa-solid fa-thumbs-up"></i>
                    </template>
                    <template #footer>

                    </template>
                </el-card>
            </el-main>
        </el-container>
    </div>
</template>

<style scoped></style>

<script setup lang="ts">
import { ref } from 'vue'

const machineName = ref("Comma")
</script>