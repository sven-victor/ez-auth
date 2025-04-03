import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

import enUS from './en-US';
import enUSApplications from './en-US/applications';
import enUSUsers from './en-US/users';
import enUSSystem from './en-US/system';
import enUSCommon from './en-US/common';
import enUSoidc from './en-US/oidc';

import arAE from './ar-AE';
import arAEApplications from './ar-AE/applications';
import arAEUsers from './ar-AE/users';
import arAESystem from './ar-AE/system';
import arAECommon from './ar-AE/common';
import arAEoidc from './ar-AE/oidc';

import deDE from './de-DE';
import deDEApplications from './de-DE/applications';
import deDEUsers from './de-DE/users';
import deDESystem from './de-DE/system';
import deDECommon from './de-DE/common';
import deDEoidc from './de-DE/oidc';

import esES from './es-ES';
import esESApplications from './es-ES/applications';
import esESUsers from './es-ES/users';
import esESSystem from './es-ES/system';
import esESCommon from './es-ES/common';
import esESoidc from './es-ES/oidc';

import frFR from './fr-FR';
import frFRApplications from './fr-FR/applications';
import frFRUsers from './fr-FR/users';
import frESSystem from './fr-FR/system';
import frESCommon from './fr-FR/common';
import frESoidc from './fr-FR/oidc';

import svSE from './sv-SE';
import svSEApplications from './sv-SE/applications';
import svSEUsers from './sv-SE/users';
import svESSystem from './sv-SE/system';
import svESCommon from './sv-SE/common';
import svESoidc from './sv-SE/oidc';


import zhCN from './zh-CN';
import zhCNApplications from './zh-CN/applications';
import zhCNUsers from './zh-CN/users';
import zhCNSystem from './zh-CN/system';
import zhCNCommon from './zh-CN/common';
import zhCNoidc from './zh-CN/oidc';

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    ns: ['applications', 'users', 'system', 'common', 'oidc'],
    defaultNS: 'translation',

    resources: {
      'en-US': {
        translation: enUS,
        applications: enUSApplications,
        users: enUSUsers,
        system: enUSSystem,
        common: enUSCommon,
        oidc: enUSoidc,
      },
      'ar-AE': {
        translation: arAE,
        applications: arAEApplications,
        users: arAEUsers,
        system: arAESystem,
        common: arAECommon,
        oidc: arAEoidc,
      },
      'de-DE': {
        translation: deDE,
        applications: deDEApplications,
        users: deDEUsers,
        system: deDESystem,
        common: deDECommon,
        oidc: deDEoidc,
      },
      'es-ES': {
        translation: esES,
        applications: esESApplications,
        users: esESUsers,
        system: esESSystem,
        common: esESCommon,
        oidc: esESoidc,
      },
      'fr-FR': {
        translation: frFR,
        applications: frFRApplications,
        users: frFRUsers,
        system: frESSystem,
        common: frESCommon,
        oidc: frESoidc,
      },
      'sv-SE': {
        translation: svSE,
        applications: svSEApplications,
        users: svSEUsers,
        system: svESSystem,
        common: svESCommon,
        oidc: svESoidc,
      },
      'zh-CN': {
        translation: zhCN,
        applications: zhCNApplications,
        users: zhCNUsers,
        system: zhCNSystem,
        common: zhCNCommon,
        oidc: zhCNoidc,
      },
    },
    fallbackLng: 'en-US',
    debug: process.env.NODE_ENV === 'development',
    interpolation: {
      escapeValue: false,
    },
  });


export default i18n; 