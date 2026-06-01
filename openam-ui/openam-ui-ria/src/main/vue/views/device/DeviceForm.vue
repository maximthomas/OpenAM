<template>
  <div class="container">
    <form
      method="post"
      class="form col-md-6 col-md-offset-3"
      autocomplete="off"
      aria-describedby="deviceFormInfo"
    >
      <fieldset>
        <p id="deviceFormInfo">{{ t('form.description') }}</p>

        <div class="form-group">
          <label class="sr-only" for="deviceUserCode">{{ t('form.code') }}</label>
          <input
            type="text"
            name="user_code"
            id="deviceUserCode"
            required
            class="form-control input-lg"
            :placeholder="t('form.code')"
          />
        </div>

        <div class="form-group">
          <button type="submit" class="btn btn-lg btn-block btn-uppercase btn-primary">
            {{ t('form.submit') }}
          </button>
        </div>
      </fieldset>
    </form>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n';

const { t } = useI18n();
</script>
