import { createRouter, createWebHistory } from 'vue-router'

import Main from '../views/Main.vue'
import Scan from '../views/Scan.vue'

const routes = [
    {
        path: '/',
        name: 'home',
        component: Main
    },
    {
        path: '/scan',
        name: 'scan',
        component: Scan
    }
]

const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes
})

export default router
