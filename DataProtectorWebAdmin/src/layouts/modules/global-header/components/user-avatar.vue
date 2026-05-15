<script setup lang="ts">
import { computed } from 'vue';
import type { VNode } from 'vue';
import { useAuthStore } from '@/store/modules/auth';
import { useSvgIcon } from '@/hooks/common/icon';

defineOptions({
  name: 'UserAvatar'
});

const authStore = useAuthStore();
const { SvgIconVNode } = useSvgIcon();

type DropdownKey = 'operator';

type DropdownOption = {
  key: DropdownKey;
  label: string;
  icon?: () => VNode;
};

const options = computed<DropdownOption[]>(() => [
  {
    label: 'Local operator session',
    key: 'operator',
    icon: SvgIconVNode({ icon: 'mdi:account-key', fontSize: 18 })
  }
]);

function handleDropdown() {
  window.$message?.info('Local operator identity is controlled by DataProtector Web Bridge.');
}
</script>

<template>
  <NDropdown placement="bottom" trigger="click" :options="options" @select="handleDropdown">
    <div>
      <ButtonIcon>
        <SvgIcon icon="mdi:account-key" class="text-icon-large" />
        <span class="text-16px font-medium">{{ authStore.userInfo.userName || 'Local Operator' }}</span>
      </ButtonIcon>
    </div>
  </NDropdown>
</template>

<style scoped></style>
