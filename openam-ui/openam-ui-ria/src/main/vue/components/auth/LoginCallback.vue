<template>
  <div class="form-group">
    <!-- PasswordCallback -->
    <template v-if="callback.type === 'PasswordCallback'">
      <label v-if="prompt" :for="inputId">{{ prompt }}</label>
      <input
        :id="inputId"
        type="password"
        class="form-control"
        :name="inputName"
        :value="modelValue"
        autocomplete="current-password"
        @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
      />
    </template>

    <!-- TextInputCallback -->
    <template v-else-if="callback.type === 'TextInputCallback'">
      <label v-if="prompt" :for="inputId">{{ prompt }}</label>
      <input
        :id="inputId"
        type="text"
        class="form-control"
        :name="inputName"
        :value="modelValue"
        autocomplete="off"
        @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
      />
    </template>

    <!-- TextOutputCallback -->
    <template v-else-if="callback.type === 'TextOutputCallback'">
      <div v-if="messageType === '4'" v-html="sanitizedMessage" />
      <div v-else class="text-output">{{ messageValue }}</div>
    </template>

    <!-- ConfirmationCallback -->
    <template v-else-if="callback.type === 'ConfirmationCallback'">
      <div class="text-center">
        <button
          v-for="(option, idx) in confirmationOptions"
          :key="idx"
          type="button"
          :class="['btn', idx === defaultOption ? 'btn-primary' : 'btn-default']"
          :name="inputName"
          :value="idx"
          @click="handleConfirmation(idx)"
        >
          {{ option }}
        </button>
      </div>
    </template>

    <!-- ChoiceCallback -->
    <template v-else-if="callback.type === 'ChoiceCallback'">
      <label v-if="prompt" :for="inputId">{{ prompt }}</label>
      <select
        :id="inputId"
        class="form-control"
        :name="inputName"
        :value="modelValue"
        @change="$emit('update:modelValue', ($event.target as HTMLSelectElement).value)"
      >
        <option v-for="(choice, idx) in choiceOptions" :key="idx" :value="idx">
          {{ choice }}
        </option>
      </select>
    </template>

    <!-- HiddenValueCallback -->
    <template v-else-if="callback.type === 'HiddenValueCallback'">
      <input type="hidden" :name="inputName" :value="modelValue" />
    </template>

    <!-- RedirectCallback -->
    <template v-else-if="callback.type === 'RedirectCallback'">
      <div class="text-center">
        <i class="fa fa-spinner fa-spin fa-2x text-primary" />
        <p>{{ $t('common.user.redirecting') || 'Redirecting...' }}</p>
      </div>
    </template>

    <!-- PollingWaitCallback -->
    <template v-else-if="callback.type === 'PollingWaitCallback'">
      <div class="panel panel-default">
        <div class="panel-body text-center">
          <h4 class="awaiting-response">
            <i class="fa fa-circle-o-notch fa-spin text-primary" />
            {{ messageValue || $t('templates.user.LoginTemplate.waitingForResponse') }}
          </h4>
        </div>
      </div>
    </template>

    <!-- Default (unknown callback type) -->
    <template v-else>
      <input type="hidden" :name="inputName" :value="modelValue" />
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';
import type { LoginCallback as LoginCallbackType } from '@/types/user';

const { t } = useI18n();

const props = defineProps<{
  callback: LoginCallbackType;
  modelValue: unknown;
  index: number;
}>();

const emit = defineEmits<{
  'update:modelValue': [value: unknown];
  'submit': [index: number];
}>();

const inputId = computed(() => {
  const name = props.callback.input?.[0]?.name || '';
  return name ? name.replace(/([A-Z])/g, (_, letter) => letter.toLowerCase()) : `callback_${props.index}`;
});

const inputName = computed(() => `callback_${props.index}`);

const prompt = computed(() => {
  const output = props.callback.output?.find((o) => o.name === 'prompt');
  const value = output?.value;
  return typeof value === 'string' ? value.replace(/:$/, '') : '';
});

const messageValue = computed(() => {
  const output = props.callback.output?.find((o) => o.name === 'message');
  return typeof output?.value === 'string' ? output.value : '';
});

const messageType = computed(() => {
  const output = props.callback.output?.find((o) => o.name === 'messageType');
  return String(output?.value ?? '');
});

const sanitizedMessage = computed(() => {
  const raw = messageValue.value;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const win = window as any;
  if (win.DOMPurify) {
    return win.DOMPurify.sanitize(raw);
  }
  return raw.replace(/</g, '&lt;').replace(/>/g, '&gt;');
});

const confirmationOptions = computed(() => {
  const output = props.callback.output?.find((o) => o.name === 'options');
  return Array.isArray(output?.value) ? output.value as string[] : [];
});

const defaultOption = computed(() => {
  const options = confirmationOptions.value;
  if (options.length <= 1) return 0;
  const output = props.callback.output?.find((o) => o.name === 'defaultOption');
  return typeof output?.value === 'number' ? output.value : 0;
});

const choiceOptions = computed(() => {
  const output = props.callback.output?.find((o) => o.name === 'choices');
  return Array.isArray(output?.value) ? output.value as string[] : [];
});

function handleConfirmation(optionIndex: number): void {
  emit('update:modelValue', optionIndex);
  emit('submit', props.index);
}
</script>
