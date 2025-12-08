import { i18n } from 'ez-console';

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

i18n.addResourceBundle('en-US', 'translation', enUS, true,).
  addResourceBundle('ar-AE', 'translation', arAE, true,).
  addResourceBundle('de-DE', 'translation', deDE, true,).
  addResourceBundle('es-ES', 'translation', esES, true,).
  addResourceBundle('fr-FR', 'translation', frFR, true,).
  addResourceBundle('sv-SE', 'translation', svSE, true,).
  addResourceBundle('zh-CN', 'translation', zhCN, true,).
  addResourceBundle('en-US', 'applications', enUSApplications, true,).
  addResourceBundle('ar-AE', 'applications', arAEApplications, true,).
  addResourceBundle('de-DE', 'applications', deDEApplications, true,).
  addResourceBundle('es-ES', 'applications', esESApplications, true,).
  addResourceBundle('fr-FR', 'applications', frFRApplications, true,).
  addResourceBundle('sv-SE', 'applications', svSEApplications, true,).
  addResourceBundle('zh-CN', 'applications', zhCNApplications, true,).
  addResourceBundle('en-US', 'users', enUSUsers, true,).
  addResourceBundle('ar-AE', 'users', arAEUsers, true,).
  addResourceBundle('de-DE', 'users', deDEUsers, true,).
  addResourceBundle('es-ES', 'users', esESUsers, true,).
  addResourceBundle('fr-FR', 'users', frFRUsers, true,).
  addResourceBundle('sv-SE', 'users', svSEUsers, true,).
  addResourceBundle('zh-CN', 'users', zhCNUsers, true,).
  addResourceBundle('en-US', 'system', enUSSystem, true,).
  addResourceBundle('ar-AE', 'system', arAESystem, true,).
  addResourceBundle('de-DE', 'system', deDESystem, true,).
  addResourceBundle('es-ES', 'system', esESSystem, true,).
  addResourceBundle('fr-FR', 'system', frESSystem, true,).
  addResourceBundle('sv-SE', 'system', svESSystem, true,).
  addResourceBundle('zh-CN', 'system', zhCNSystem, true,).
  addResourceBundle('en-US', 'common', enUSCommon, true,).
  addResourceBundle('ar-AE', 'common', arAECommon, true,).
  addResourceBundle('de-DE', 'common', deDECommon, true,).
  addResourceBundle('es-ES', 'common', esESCommon, true,).
  addResourceBundle('fr-FR', 'common', frESCommon, true,).
  addResourceBundle('sv-SE', 'common', svESCommon, true,).
  addResourceBundle('zh-CN', 'common', zhCNCommon, true,).
  addResourceBundle('en-US', 'oidc', enUSoidc, true,).
  addResourceBundle('ar-AE', 'oidc', arAEoidc, true,).
  addResourceBundle('de-DE', 'oidc', deDEoidc, true,).
  addResourceBundle('es-ES', 'oidc', esESoidc, true,).
  addResourceBundle('fr-FR', 'oidc', frESoidc, true,).
  addResourceBundle('sv-SE', 'oidc', svESoidc, true,).
  addResourceBundle('zh-CN', 'oidc', zhCNoidc, true,);