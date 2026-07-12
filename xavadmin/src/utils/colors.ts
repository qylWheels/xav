import { useCssVar } from '@vueuse/core'

// Colors.
const primaryColor = useCssVar('--el-color-primary')
const successColor = useCssVar('--el-color-success')
const warningColor = useCssVar('--el-color-warning')
const infoColor = useCssVar('--el-color-info')
const dangerColor = useCssVar('--el-color-danger')

export { primaryColor, successColor, warningColor, infoColor, dangerColor }
