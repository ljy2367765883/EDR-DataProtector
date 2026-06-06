import type { App } from 'vue';
import { createI18n } from 'vue-i18n';
import { localStg } from '@/utils/storage';
import messages from './locale';

const i18n = createI18n({
  locale: localStg.get('lang') || 'zh-CN',
  fallbackLocale: 'en',
  messages,
  legacy: false
});

/**
 * Setup plugin i18n
 *
 * @param app
 */
export function setupI18n(app: App) {
  app.use(i18n);
}

const runtimeI18n = i18n as unknown as {
  global: {
    t: unknown;
    locale: {
      value: string;
    };
  };
};

const translate = runtimeI18n.global.t;

export const $t = translate as App.I18n.$T;

export function setLocale(locale: App.I18n.LangType) {
  runtimeI18n.global.locale.value = locale;

  document?.querySelector('html')?.setAttribute('lang', locale);
}

export function getLocale(): App.I18n.LangType {
  return runtimeI18n.global.locale.value as App.I18n.LangType;
}
