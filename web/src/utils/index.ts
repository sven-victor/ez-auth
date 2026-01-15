// Date formatting
export const formatDate = (date: Date | string | number | undefined, format: string = 'YYYY-MM-DDTHH:mm:ssZ'): string => {
  if (!date) return '';
  const d = date instanceof Date ? date : new Date(date);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  const hours = String(d.getHours()).padStart(2, '0');
  const minutes = String(d.getMinutes()).padStart(2, '0');
  const seconds = String(d.getSeconds()).padStart(2, '0');

  return format
    .replace('YYYY', String(year))
    .replace('MM', month)
    .replace('DD', day)
    .replace('HH', hours)
    .replace('mm', minutes)
    .replace('ss', seconds);
};

export const toLDAPAttrs = (attrs: string): API.LDAPAttrs[] => {
  return attrs.split('\n').map((attr: string) => {
    const base64SplitIndex = attr.indexOf("::")
    if (base64SplitIndex > 0) {
      const name = attr.slice(0, base64SplitIndex);
      const value = attr.slice(base64SplitIndex + 2);
      return { name: name.trim(), value: value.trim(), user_attr: true, base64: true };
    }
    const [name, value] = attr.split(':');
    if (name.length == 0) {
      return null;
    }
    return { name: name.trim(), value: value.trim(), user_attr: true, base64: false };
  }).filter((attr) => attr !== null);
}

export const getApplicationDisplayName = (application: API.Application | undefined, lang: string) => {
  if (!application) {
    return '';
  }
  if (application.display_name_i18n?.[lang]) {
    return `${application.display_name_i18n[lang]}`
  }
  if (application.display_name) {
    return `${application.display_name}`
  }
  return application.name
}

export const getApplicationDescription = (application: API.Application | undefined, lang: string) => {
  if (!application) {
    return '';
  }
  if (application.description_i18n?.[lang]) {
    return application.description_i18n[lang]
  }
  return application.description
}
