import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
void i18n.use(initReactI18next).init({ lng: 'zh-CN', fallbackLng: 'zh-CN', interpolation: { escapeValue: false }, resources: { 'zh-CN': { translation: { name: '开发者门户', catalog: 'API 目录', applications: '我的应用', requests: '凭证申请', profile: '我的账号', login: '登录', register: '注册', noTenant: '选择公开门户以开始探索 API' } } } });
export default i18n;
