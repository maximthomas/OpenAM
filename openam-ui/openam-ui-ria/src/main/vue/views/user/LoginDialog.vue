<template>
  <teleport to="body">
    <div
      v-if="showDialog"
      class="modal fade in login-dialog"
      tabindex="-1"
      role="dialog"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header bg-primary">
            <h4 class="modal-title">{{ $t('common.form.sessionExpired') || 'Session Expired' }}</h4>
          </div>
          <div class="modal-body">
            <LoginView background-login @success="handleSuccess" />
          </div>
        </div>
      </div>
    </div>
    <div v-if="showDialog" class="modal-backdrop fade in" />
  </teleport>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { useAuth } from '@/composables/useAuth';
import LoginView from '@/views/user/LoginView.vue';

const auth = useAuth();
const showDialog = ref(false);

function handleSuccess(): void {
  showDialog.value = false;
}

watch(() => auth.initialized.value, (initialized) => {
  if (initialized && !auth.isAuthenticated.value) {
    showDialog.value = true;
  }
});
</script>

<style scoped>
.modal {
  display: block;
  z-index: 1060;
}

.modal-backdrop {
  z-index: 1055;
}
</style>
