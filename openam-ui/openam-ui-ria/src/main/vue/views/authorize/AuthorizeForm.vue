<template>
  <div>
    <div class="page-header col-md-6 col-md-offset-3 wordwrap">
      <h1 class="text-center"><span v-html="oauth2Data.displayName" /></h1>
      <p v-if="oauth2Data.displayDescription" class="text-center">
        <em><span v-html="oauth2Data.displayDescription" /></em>
      </p>
    </div>

    <form :action="oauth2Data.formTarget" method="post" class="form col-md-6 col-md-offset-3" autocomplete="off">
      <fieldset>
        <p v-if="noScopes">{{ t('form.noScopes') }}</p>
        <p v-else>{{ t('form.description') }}</p>

        <ScopeList
          :items="oauth2Data.displayScopes"
          id-prefix="oauth2Scope"
        />
        <ScopeList
          :items="oauth2Data.displayClaims"
          id-prefix="oauth2Claims"
        />

        <p v-if="oauth2Data.userName">
          {{ t('form.signedInAs') }}
          <span class="text-primary"><span v-html="oauth2Data.userName" /></span>
        </p>

        <!-- Optional hidden fields -->
        <input v-if="oauth2Data.realm" type="hidden" name="realm" aria-hidden="true" :value="oauth2Data.realm" />
        <input v-if="oauth2Data.redirectUri" type="hidden" name="redirect_uri" aria-hidden="true" :value="oauth2Data.redirectUri" />
        <input v-if="oauth2Data.scope" type="hidden" name="scope" aria-hidden="true" :value="oauth2Data.scope" />
        <input v-if="oauth2Data.state" type="hidden" name="state" aria-hidden="true" :value="oauth2Data.state" />
        <input v-if="oauth2Data.nonce" type="hidden" name="nonce" aria-hidden="true" :value="oauth2Data.nonce" />
        <input v-if="oauth2Data.acr" type="hidden" name="acr" aria-hidden="true" :value="oauth2Data.acr" />
        <input v-if="oauth2Data.userCode" type="hidden" name="user_code" aria-hidden="true" :value="oauth2Data.userCode" />

        <!-- Required hidden fields -->
        <input type="hidden" name="response_type" aria-hidden="true" :value="oauth2Data.responseType" />
        <input type="hidden" name="client_id" aria-hidden="true" :value="oauth2Data.clientId" />
        <input type="hidden" name="csrf" aria-hidden="true" :value="oauth2Data.csrf" />

        <div class="form-group clearfix">
          <div class="pull-right">
            <button type="submit" name="decision" class="btn btn-default" value="deny">{{ t('form.deny') }}</button>
            <button type="submit" name="decision" class="btn btn-primary" value="allow">{{ t('form.allow') }}</button>
          </div>
          <div v-if="oauth2Data.isSaveConsentEnabled" class="pull-left checkbox">
            <label for="saveConsent">
              <input type="checkbox" name="save_consent" id="saveConsent" />
            </label>{{ t('form.save') }}
          </div>
        </div>
      </fieldset>
    </form>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n';
import type { AuthorizePageData } from '@/types/authorize';
import ScopeList from '@/views/authorize/ScopeList.vue';

const { t } = useI18n();

const props = defineProps<{
  pageData: AuthorizePageData;
}>();

const oauth2Data = props.pageData.oauth2Data!;
const noScopes = props.pageData.noScopes ?? false;
</script>
