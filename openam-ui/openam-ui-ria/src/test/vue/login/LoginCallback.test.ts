import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import { createI18n } from 'vue-i18n';
import LoginCallback from '@/components/auth/LoginCallback.vue';

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  fallbackLocale: 'en',
  messages: {},
  messageCompiler: (message: string) => () => message,
});

function createCallback(type: string, output: Array<{ name: string; value: unknown }> = [], input?: Array<{ name: string; value: unknown }>) {
  return {
    type,
    output,
    input: input || [{ name: 'input', value: '' }],
  };
}

function mountCallback(props: { callback: ReturnType<typeof createCallback>; modelValue: unknown; index: number }) {
  return mount(LoginCallback, {
    props,
    global: { plugins: [i18n] },
  });
}

describe('LoginCallback', () => {
  describe('PasswordCallback', () => {
    it('renders a password input', () => {
      const callback = createCallback('PasswordCallback', [{ name: 'prompt', value: 'Password' }], [{ name: 'password', value: '' }]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      expect(wrapper.find('input[type="password"]').exists()).toBe(true);
    });

    it('displays the prompt label', () => {
      const callback = createCallback('PasswordCallback', [{ name: 'prompt', value: 'Enter Password:' }]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      expect(wrapper.text()).toContain('Enter Password');
    });

    it('emits update:modelValue on input', async () => {
      const callback = createCallback('PasswordCallback', [{ name: 'prompt', value: 'Password' }]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      await wrapper.find('input').setValue('secret');
      expect(wrapper.emitted('update:modelValue')).toBeTruthy();
    });
  });

  describe('TextInputCallback', () => {
    it('renders a text input', () => {
      const callback = createCallback('TextInputCallback', [{ name: 'prompt', value: 'User Name' }]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      expect(wrapper.find('input[type="text"]').exists()).toBe(true);
    });

    it('displays the prompt label', () => {
      const callback = createCallback('TextInputCallback', [{ name: 'prompt', value: 'Username:' }]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      expect(wrapper.text()).toContain('Username');
    });
  });

  describe('TextOutputCallback', () => {
    it('renders message text', () => {
      const callback = createCallback('TextOutputCallback', [
        { name: 'message', value: 'Welcome to OpenAM' },
        { name: 'messageType', value: 0 },
      ]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      expect(wrapper.text()).toContain('Welcome to OpenAM');
    });

    it('renders script content for messageType 4', () => {
      const callback = createCallback('TextOutputCallback', [
        { name: 'message', value: '<script>alert("xss")</script>' },
        { name: 'messageType', value: '4' },
      ]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      expect(wrapper.find('div').exists()).toBe(true);
    });
  });

  describe('ConfirmationCallback', () => {
    it('renders buttons for each option', () => {
      const callback = createCallback('ConfirmationCallback', [
        { name: 'prompt', value: '' },
        { name: 'options', value: ['Login', 'Cancel'] },
        { name: 'optionType', value: 0 },
        { name: 'defaultOption', value: 0 },
        { name: 'value', value: false },
      ]);
      const wrapper = mountCallback({ callback, modelValue: 0, index: 0 });
      const buttons = wrapper.findAll('button');
      expect(buttons).toHaveLength(2);
      expect(buttons[0].text()).toBe('Login');
      expect(buttons[1].text()).toBe('Cancel');
    });

    it('marks default option as btn-primary', () => {
      const callback = createCallback('ConfirmationCallback', [
        { name: 'options', value: ['OK', 'Cancel'] },
        { name: 'defaultOption', value: 0 },
      ]);
      const wrapper = mountCallback({ callback, modelValue: 0, index: 0 });
      expect(wrapper.findAll('button')[0].classes()).toContain('btn-primary');
      expect(wrapper.findAll('button')[1].classes()).toContain('btn-default');
    });

    it('emits submit when button is clicked', async () => {
      const callback = createCallback('ConfirmationCallback', [
        { name: 'options', value: ['Login'] },
        { name: 'defaultOption', value: 0 },
      ]);
      const wrapper = mountCallback({ callback, modelValue: 0, index: 2 });
      await wrapper.findAll('button')[0].trigger('click');
      expect(wrapper.emitted('submit')).toBeTruthy();
      expect(wrapper.emitted('submit')![0]).toEqual([2]);
    });
  });

  describe('ChoiceCallback', () => {
    it('renders a select with choices', () => {
      const callback = createCallback('ChoiceCallback', [
        { name: 'prompt', value: 'Select option' },
        { name: 'choices', value: ['Option A', 'Option B', 'Option C'] },
        { name: 'defaultChoice', value: 0 },
      ]);
      const wrapper = mountCallback({ callback, modelValue: '0', index: 0 });
      const options = wrapper.findAll('option');
      expect(options).toHaveLength(3);
      expect(options[0].text()).toBe('Option A');
    });
  });

  describe('HiddenValueCallback', () => {
    it('renders a hidden input', () => {
      const callback = createCallback('HiddenValueCallback', [
        { name: 'prompt', value: 'hidden' },
        { name: 'value', value: 'secret-data' },
      ], [{ name: 'input', value: 'secret-data' }]);
      const wrapper = mountCallback({ callback, modelValue: 'secret-data', index: 0 });
      expect(wrapper.find('input[type="hidden"]').exists()).toBe(true);
    });
  });

  describe('RedirectCallback', () => {
    it('renders redirect spinner', () => {
      const callback = createCallback('RedirectCallback', [
        { name: 'redirectUrl', value: 'https://example.com' },
        { name: 'trackingCookie', value: true },
      ]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      expect(wrapper.find('.fa-spinner').exists()).toBe(true);
    });
  });

  describe('PollingWaitCallback', () => {
    it('renders polling spinner with message', () => {
      const callback = createCallback('PollingWaitCallback', [
        { name: 'waitTime', value: 5000 },
        { name: 'message', value: 'Waiting for response...' },
      ]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      expect(wrapper.find('.fa-circle-o-notch').exists()).toBe(true);
      expect(wrapper.text()).toContain('Waiting for response...');
    });
  });

  describe('Unknown callback type', () => {
    it('renders a hidden input for unknown types', () => {
      const callback = createCallback('UnknownCallbackType');
      const wrapper = mountCallback({ callback, modelValue: '', index: 0 });
      expect(wrapper.find('input[type="hidden"]').exists()).toBe(true);
    });
  });

  describe('input naming', () => {
    it('uses callback_N format for input name', () => {
      const callback = createCallback('PasswordCallback', [{ name: 'prompt', value: 'Password' }]);
      const wrapper = mountCallback({ callback, modelValue: '', index: 3 });
      expect(wrapper.find('input').attributes('name')).toBe('callback_3');
    });
  });
});
