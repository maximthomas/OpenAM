import { computed } from 'vue';
import { useRoute } from 'vue-router';

export function useRealm() {
  const route = useRoute();

  const realmPath = computed(() => {
    const raw = route.params.realmPath;
    if (Array.isArray(raw)) return raw[0] ?? '';
    return raw ?? '';
  });

  const decodedRealmPath = computed(() => {
    return decodeURIComponent(realmPath.value);
  });

  return {
    realmPath,
    decodedRealmPath,
  };
}
