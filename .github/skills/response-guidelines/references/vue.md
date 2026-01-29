---
language: vue
description: Vue 语言注释规则与示例
---

# Vue 语言注释规则

本文件为 Vue 组件的注释规范参考, 配合主 skill 使用。适用于 Vue 3 单文件组件（SFC）及 Composition API。

## 环境与依赖版本

在处理 Vue 项目时, 助理应自行执行以下操作以了解项目环境：

1. 运行 `node -v` 获取当前 Node.js 版本。
2. 运行 `pnpm -v` 获取当前 pnpm 版本。
3. 阅读项目根目录的 `package.json` 文件, 了解：
   - `dependencies` 中的运行时依赖及版本。
   - `devDependencies` 中的开发依赖及版本。
   - `engines` 字段指定的 Node/pnpm 版本要求（如有）。
   - `vue`、`vite`、`typescript` 等核心依赖的版本。

这些信息有助于生成与项目兼容的代码和注释。

## 注释风格

- 组件顶部使用 HTML 注释 `<!-- -->` 或 `<script>` 内使用 JSDoc 风格 `/** */`。
- Props、Emits、Methods 使用 JSDoc 注释。
- 模板中复杂逻辑使用 HTML 注释 `<!-- 说明 -->`。
- TypeScript 类型注释优先使用 TSDoc 风格。

## 组件注释模版

### Script Setup（Vue 3 Composition API）

```vue
<script setup lang="ts">
/**
 * 组件 Props 定义。
 */
interface Props {
  /** userId, 用户唯一标识。 */
  userId: string
  /** userName, 用户显示名称。 */
  userName: string
  /** avatar, 用户头像 URL, 可选。 */
  avatar?: string
}

const props = defineProps<Props>()

/**
 * 组件事件定义。
 */
interface Emits {
  /** click, 点击卡片时触发, 返回用户 ID。 */
  (e: 'click', userId: string): void
  /** delete, 删除用户时触发, 返回用户 ID。 */
  (e: 'delete', userId: string): void
}

const emit = defineEmits<Emits>()

/**
 * handleClick 处理卡片点击事件。
 * 触发 click 事件并传递用户 ID。
 */
function handleClick(): void {
  emit('click', props.userId)
}
</script>
```

## 模板注释

```vue
<template>
  <div class="user-card">
    <!-- 用户头像区域 -->
    <div class="avatar">
      <img :src="avatar" :alt="userName" />
    </div>

    <!-- 用户信息区域 -->
    <div class="info">
      <h3>{{ userName }}</h3>
      <!-- 条件渲染: 仅在有简介时显示 -->
      <p v-if="bio">{{ bio }}</p>
    </div>

    <!-- 操作按钮区域 -->
    <div class="actions">
      <!-- 编辑按钮, 需要编辑权限 -->
      <button v-if="canEdit" @click="handleEdit">编辑</button>
      <!-- 删除按钮, 需要确认 -->
      <button @click="handleDelete">删除</button>
    </div>
  </div>
</template>
```

## Composables（组合式函数）注释

```typescript
/**
 * useUser 用户相关组合式函数。
 * 用途: 封装用户数据获取与状态管理逻辑。
 *   - userId, 用户 ID。
 * 返回值 object, 包含 user 响应式对象、loading 状态及 fetchUser 方法。
 */
export function useUser(userId: Ref<string>) {
  /** user, 用户数据响应式对象。 */
  const user = ref<User | null>(null)

  /** loading, 加载状态。 */
  const loading = ref(false)

  /** error, 错误信息。 */
  const error = ref<Error | null>(null)

  /**
   * fetchUser 获取用户数据。
   * 从 API 获取用户信息并更新状态。
   */
  async function fetchUser(): Promise<void> {
    loading.value = true
    error.value = null
    try {
      user.value = await api.getUser(userId.value)
    } catch (e) {
      error.value = e as Error
    } finally {
      loading.value = false
    }
  }

  // 监听 userId 变化自动获取
  watch(userId, fetchUser, { immediate: true })

  return { user, loading, error, fetchUser }
}
```

## 样式注释

```vue
<style lang="scss" scoped>

// 卡片容器, 使用 flex 布局
.user-card {
  display: flex;
  padding: 16px;
  border-radius: 8px;
}


// 头像容器, 固定尺寸
.avatar {
  width: 64px;
  height: 64px;
  border-radius: 50%;
  overflow: hidden;
}

</style>
```

## 静态检查工具

运行检查命令:

```bash
# ESLint 检查
pnpm lint

# TypeScript 类型检查
pnpm type-check

# 格式化
pnpm format
```

## 保留原注释示例

```vue
<script setup lang="ts">
/**
 * 原注释: // Button component for user actions.
 * ActionButton 用户操作按钮组件。
 * 用途: 提供统一样式的操作按钮, 支持加载状态与禁用。
 */

interface Props {
  /** 原注释: // Button label text. */
  /** label, 按钮显示文本。 */
  label: string
  /** loading, 是否显示加载状态, 默认 false。 */
  loading?: boolean
  /** disabled, 是否禁用按钮, 默认 false。 */
  disabled?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  loading: false,
  disabled: false
})
</script>
```

---

注: 本文件为 Vue 语言特定规则, 通用规则请参阅主 `SKILL.md`。
