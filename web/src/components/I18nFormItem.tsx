/**
 * Copyright 2026 Sven Victor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { i18n, AllLangUIConfig } from "ez-console";
import { Tabs, Input, Form } from "antd";
import { createStyles } from 'antd-style';

const useStyles = createStyles(({ css }) => {
  return {
    i18nFormItem: css`
    .ant-tabs-nav{
      margin-bottom: 8px;
    }
  `,
  }
});

interface I18nFormItemProps {
  t: (key: string, options?: { defaultValue?: string } & Record<string, any>) => string;
  name: string;
  i18nName?: string;
  formComponent?: React.ComponentType<any>;
  childRender?: (item: { lang: string, label: string }) => React.ReactNode;
}

export const I18nFormItem: React.FC<I18nFormItemProps> = ({
  t,
  name,
  i18nName = `${name}_i18n`,
  childRender = () => {
    return <Input />
  }
}) => {
  const { styles } = useStyles();
  return <Tabs
    className={styles.i18nFormItem} tabBarStyle={{ marginBottom: '0 0 8px 0' }}
    items={[{
      key: "default",
      label: t(`default`, { defaultValue: 'Default' }),
      children: <Form.Item name={name} style={{ marginBottom: 0 }}>
        {childRender({ lang: "default", label: t(`default`, { defaultValue: 'Default' }) })}
      </Form.Item>,
      forceRender: true,
    }, ...AllLangUIConfig.map(item => ({
      key: item.lang,
      label: i18n.language !== item.lang ? t(`${item.lang}`, { defaultValue: item.label, lang: item.label }) : item.label,
      children: <Form.Item name={[i18nName, item.lang]} style={{ marginBottom: 0 }}>
        {childRender(item)}
      </Form.Item>,
      forceRender: true,
    }))]
    }
  />

};

export default I18nFormItem;

