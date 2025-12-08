import React, { useState } from 'react';
import {
  Table,
  Card,
  Button,
  Tag,
  Space,
  Input,
  Row,
  Col,
  Form,
  Select,
  message,
  TableColumnType
} from 'antd';
import {
  SearchOutlined,
  ReloadOutlined,
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  EyeOutlined,
  AppstoreOutlined,
} from '@ant-design/icons';
import { Link, useNavigate } from 'react-router-dom';
import { PermissionGuard } from 'ez-console';
import { getApplications, deleteApplication } from '@/api/application';
import { formatDate, getApplicationDescription, getApplicationDisplayName } from '@/utils';
import { PAGINATION } from '@/constants';
import { useTranslation } from 'ez-console';
import { useRequest } from 'ahooks';
import { Avatar, Actions } from 'ez-console';

const { Option } = Select;

// Application list page
const ApplicationList: React.FC = () => {
  const navigate = useNavigate();
  const { t, i18n } = useTranslation("applications");
  const { t: tCommon } = useTranslation("common");
  const [searchForm] = Form.useForm();

  // Data status
  const [applications, setApplications] = useState<API.Application[]>([]);
  const [total, setTotal] = useState(0);

  // Query parameters
  const [queryParams, setQueryParams] = useState({
    current: PAGINATION.DEFAULT_CURRENT,
    page_size: PAGINATION.DEFAULT_PAGE_SIZE,
    keywords: undefined,
    status: undefined,
  });

  // Load application list
  const { run: fetchApplications, loading } = useRequest(async () => {
    return getApplications(queryParams.keywords, queryParams.status, queryParams.current, queryParams.page_size)
  }, {
    onSuccess: (result) => {
      setApplications(result.data || []);
      setTotal(result.total || 0);
    },
    onError: (error) => {
      message.error(t('loadError', { defaultValue: 'Failed to load applications: {{error}}', error: error }));
    },
    refreshDeps: [queryParams],
  });


  // Search form submission
  const handleSearch = (values: any) => {
    setQueryParams({
      ...queryParams,
      current: PAGINATION.DEFAULT_CURRENT, // Reset to the first page
      keywords: values.keywords,
      status: values.status,
    });
  };

  // Reset search form
  const handleReset = () => {
    searchForm.resetFields();
    setQueryParams({
      current: PAGINATION.DEFAULT_CURRENT,
      page_size: PAGINATION.DEFAULT_PAGE_SIZE,
      keywords: undefined,
      status: undefined,
    });
  };

  // Page change event
  const handlePageChange = (page: number, pageSize: number) => {
    setQueryParams(prev => ({
      ...prev,
      current: page,
      page_size: pageSize,
    }));
  };

  // Delete application
  const handleDelete = async (id: string) => {
    try {
      await deleteApplication(id);
      message.success(t('deleteSuccess', { defaultValue: 'Application deleted successfully' }));
      fetchApplications();
    } catch (error) {
      console.error('Failed to delete application:', error);
      message.error(t('deleteError', { defaultValue: 'Failed to delete application: {{error}}', error }));
    }
  };

  // Build table columns
  const columns: TableColumnType<API.Application>[] = [
    {
      title: t('name', { defaultValue: 'Name' }),
      key: 'name',
      width: 200,
      render: (_: any, record: API.Application) => (
        <div style={{ display: 'flex', alignItems: 'center', minWidth: 200 }}>
          <Avatar
            size="small"
            icon={<AppstoreOutlined />}
            src={record.icon}
            style={{ marginRight: 8 }}
          />
          <Link to={`/applications/${record.id}`}>{getApplicationDisplayName(record, i18n.language) || record.name}</Link>
        </div>
      ),
    },
    {
      title: t('description', { defaultValue: 'Description' }),
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      responsive: ['sm'],
      render: (_: any, record: API.Application,) => {
        return getApplicationDescription(record, i18n.language) || record.description;
      }
    },
    {
      title: t('uri', { defaultValue: 'URI' }),
      dataIndex: 'uri',
      // width: 300,
      key: 'uri',
      ellipsis: true,
      responsive: ['lg'],
      render: (_: any, record: API.Application) => {
        return <Link to={record.uri} target="_blank">{record.uri}</Link>;
      }
    },
    {
      title: t('source', { defaultValue: 'Source' }),
      dataIndex: 'source',
      width: 120,
      responsive: ['md'],
      key: 'source',
      render: (source: string) => {
        switch (source) {
          case 'ldap':
            return <Tag color="blue">{t('sourceLdap', { defaultValue: 'LDAP' })}</Tag>;
          case 'local':
            return <Tag color="default">{t('sourceLocal', { defaultValue: 'Local' })}</Tag>;
          default:
            return <Tag color="red">{source}</Tag>;
        }
      },
    },
    {
      title: t('status', { defaultValue: 'Status' }),
      dataIndex: 'status',
      width: 120,
      responsive: ['md'],
      key: 'status',
      render: (status: string) => {
        switch (status) {
          case 'active':
            return <Tag color="success">{t('statusEnum.active', { defaultValue: 'Active' })}</Tag>;
          case 'inactive':
            return <Tag color="error">{t('statusEnum.inactive', { defaultValue: 'Inactive' })}</Tag>;
          default:
            return <Tag>{t(`statusEnum.${status}`, { defaultValue: status })}</Tag>;
        }
      },
    },
    {
      title: t('createdAt', { defaultValue: 'Created At' }),
      dataIndex: 'created_at',
      width: 200,
      key: 'created_at',
      render: (date: string) => formatDate(date),
      responsive: ['xl'],
    },
    {
      title: t('updatedAt', { defaultValue: 'Updated At' }),
      dataIndex: 'updated_at',
      width: 200,
      key: 'updated_at',
      responsive: ['xxl'],
      render: (date: string) => formatDate(date),
    },
    {
      title: tCommon('actions', { defaultValue: 'Actions' }),
      key: 'action',
      width: 120,
      render: (_: any, record: API.Application) => (
        <Actions actions={[
          {
            key: "view",
            permission: "applications:view",
            icon: <EyeOutlined />,
            tooltip: tCommon('view', { defaultValue: 'View' }),
            onClick: async () => navigate(`/applications/${record.id}`),
          },
          {
            key: "edit",
            permission: "applications:edit",
            icon: <EditOutlined />,
            tooltip: tCommon('edit', { defaultValue: 'Edit' }),
            onClick: async () => navigate(`/applications/${record.id}/edit`),
          },
          {
            key: "delete",
            permission: "applications:delete",
            icon: <DeleteOutlined />,
            tooltip: tCommon('delete', { defaultValue: 'Delete' }),
            confirm: {
              title: t('deleteConfirm', { defaultValue: 'Are you sure to delete this application?' }),
              onConfirm: () => handleDelete(record.id),
              okText: tCommon('confirm', { defaultValue: 'Confirm' }),
              cancelText: tCommon('cancel', { defaultValue: 'Cancel' }),
            },
          },
        ]} />
      ),
    },
  ];

  return (
    <div>
      {/* Search form */}
      <Card style={{ marginBottom: 16 }}>
        <Form
          form={searchForm}
          onFinish={handleSearch}
          layout="inline"
        >
          <Row gutter={16} style={{ width: '100%' }}>
            <Col span={6}>
              <Form.Item name="keywords">
                <Input
                  placeholder={t('keywordsPlaceholder', { defaultValue: 'Search by name, client ID' })}
                  prefix={<SearchOutlined />}
                  allowClear
                />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="status">
                <Select
                  placeholder={t('status', { defaultValue: 'Status' })}
                  allowClear
                  style={{ width: '100%' }}
                >
                  <Option value="active">{t('statusEnum.active', { defaultValue: 'Active' })}</Option>
                  <Option value="inactive">{t('statusEnum.inactive', { defaultValue: 'Inactive' })}</Option>
                  <Option value="deleted">{t('statusEnum.deleted', { defaultValue: 'Deleted' })}</Option>
                </Select>
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item>
                <Space>
                  <Button type="primary" htmlType="submit" icon={<SearchOutlined />}>
                    {tCommon('search', { defaultValue: 'Search' })}
                  </Button>
                  <Button onClick={handleReset} icon={<ReloadOutlined />}>
                    {tCommon('reset', { defaultValue: 'Reset' })}
                  </Button>
                </Space>
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Card>

      {/* Data table */}
      <Card>
        {/* Table toolbar */}
        <div style={{ marginBottom: 16 }}>
          <Row justify="space-between" align="middle">
            <Col>
              <Button
                type="primary"
                onClick={fetchApplications}
                icon={<ReloadOutlined />}
              >
                {tCommon('refresh', { defaultValue: 'Refresh' })}
              </Button>
            </Col>
            <Col>
              <PermissionGuard permission="applications:create">
                <Button
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={() => navigate('/applications/create')}
                >
                  {t('create', { defaultValue: 'Create' })}
                </Button>
              </PermissionGuard>
            </Col>
          </Row>
        </div>

        {/* Table */}
        <Table
          columns={columns}
          dataSource={applications}
          rowKey="id"
          loading={loading}
          pagination={{
            current: queryParams.current,
            pageSize: queryParams.page_size,
            total: total,
            onChange: handlePageChange,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total) => tCommon('totalItems', { total }),
          }}
        />
      </Card>
    </div>
  );
};

export default ApplicationList; 