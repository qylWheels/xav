<script setup lang="ts">
</script>

<template>
    <el-container>
        <el-aside width="15%">
            <el-menu :default-active="$route.path" router>
                <el-menu-item index="/dashboard">
                    <el-icon>
                        <Aim />
                    </el-icon>
                    <template #title>
                        Dashboard
                    </template>
                </el-menu-item>
                <el-menu-item index="/devices">
                    <el-icon>
                        <Monitor />
                    </el-icon>
                    <template #title>
                        Devices
                    </template>
                </el-menu-item>
                <el-menu-item index="/notifications">
                    <el-icon>
                        <Bell />
                    </el-icon>
                    <template #title>
                        Notifications
                    </template>
                </el-menu-item>
                <el-menu-item index="/settings">
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
                <el-row>
                    <h4>Xav Admin Management Platform</h4>
                </el-row>
            </el-header>
            <el-main>
                <router-view />
            </el-main>
        </el-container>
    </el-container>

</template>
