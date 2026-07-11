<script setup lang="ts">
</script>

<template>
    <el-container>
        <el-aside>
            <el-menu :default-active="$route.path" router>
                <el-menu-item index="/dashboard">
                    <el-icon>
                        <Monitor />
                    </el-icon>
                    <template #title>
                        Dashboard
                    </template>
                </el-menu-item>
                <el-menu-item index="/scan">
                    <el-icon>
                        <Search />
                    </el-icon>
                    <template #title>
                        Scan
                    </template>
                </el-menu-item>
                <el-menu-item index="/procmon">
                    <el-icon>
                        <View />
                    </el-icon>
                    <template #title>
                        Process Monitor
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
                <h2>Xav Admin Management Platform</h2>
            </el-header>
            <el-main>
                <router-view />
            </el-main>
        </el-container>
    </el-container>

</template>

<style scoped></style>
