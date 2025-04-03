import i18n from "@/i18n";
import { Tabs, Input, Form } from "antd";
import { AllLangUIConfig } from "./LanguageSwitch";
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
  return <Tabs className={styles.i18nFormItem} tabBarStyle={{ marginBottom: '0 0 8px 0' }}>
    <Tabs.TabPane tab={t(`default`, { defaultValue: 'Default' })} key="default" forceRender={true}>
      <Form.Item name={name} style={{ marginBottom: 0 }}>
        {childRender({ lang: "default", label: t(`default`, { defaultValue: 'Default' }) })}
      </Form.Item>
    </Tabs.TabPane>
    {AllLangUIConfig.map(item => (
      <Tabs.TabPane tab={i18n.language !== item.lang ? t(`${item.lang}`, { defaultValue: item.label, lang: item.label }) : item.label} key={item.lang} forceRender={true}>
        <Form.Item name={[i18nName, item.lang]} style={{ marginBottom: 0 }}>
          {childRender(item)}
        </Form.Item>
      </Tabs.TabPane>
    ))}
  </Tabs>

};

export default I18nFormItem;

