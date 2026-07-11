import { createRouter, createWebHistory } from 'vue-router'

import Dashboard from '@/views/Dashboard.vue'
import Scan from '@/views/Scan.vue'
import ProcessMonitor from '@/views/ProcessMonitor.vue'
import Settings from '@/views/Settings.vue'

const routes = [
    {
        path: '/',
        redirect: '/dashboard'
    },
    {
        path: '/dashboard',
        name: 'dashboard',
        component: Dashboard
    },
    {
        path: '/scan',
        name: 'scan',
        component: Scan
    },
    {
        path: '/procmon',
        name: 'procmon',
        component: ProcessMonitor
    },
    {
        path: '/settings',
        name: 'settings',
        component: Settings
    },
]

const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes
})

export default router
