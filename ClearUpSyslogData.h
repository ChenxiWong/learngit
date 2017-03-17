// Last Update:2017-03-16 16:07:20
/**
 * @file ClearUpSyslogData.h
 * @brief 
 * @author wangchenxi
 * @version 0.1.00
 * @date 2017-03-16
 */

#ifndef _CLEAR_UP_SYSLOG_DATA_H
#define _CLEAR_UP_SYSLOG_DATA_H

enum WHICH_MEM 
{
    TIME_STR,
    ID_STR,
    MSG_STR,
    HOST_STR,
};

class msg_base
{
    public:
        msg_base()
        {
        }
        virtual ~msg_base()
        {
        }
        string m_time_str;
        string m_id_str;
        string m_msg_str;
        string m_host_str;
        bool get_one_msg_mem(string& dst_str,WHICH_MEM tmp_enum)
        {
            switch(tmp_enum)
            {
                case TIME_STR:
                    {
                        dst_str = m_time_str;
                        return true;
                    }
                case ID_STR:
                    {
                        dst_str = m_id_str;
                        return true;
                    }
                case MSG_STR:
                    {
                        dst_str = m_msg_str;
                        return true;
                    }
                case HOST_STR:
                    {
                        dst_str = m_host_str;
                        return true;
                    }
                default:
                    {
                        dst_str.clear();
                        return false;
                    }
            }
        }
};


class arrange_syslog_data_to_table
{
    public:
        arrange_syslog_data_to_table()
        {
        }
        virtual ~arrange_syslog_data_to_table()
        {
        }
        time_t m_start_time;
        time_t m_new_time;
        map<string, string> m_result_map;
        list<handle_base*> m_handle_list;
        list<msg_base*> m_msg_base_list;
        void work()
        {
        }
};



class handle_base
{
    public:
        handle_base()
        {
        }
        virtual ~handle_base()
        {
        }
        virtual bool run(arrange_syslog_data_to_table* dst_msg, msg_base* msg)= 0;
}

class func_base : virtual public handle_base
{
    protected:
        WHICH_MEM m_this_mem;
    public:
        func_base()
        {
        }
        virtual ~func_base()
        {
        }
        virtual bool run(arrange_syslog_data_to_table* dst_msg, msg_base* msg)= 0;
};

class work_handle
{
    public:
        work_handle()
        {
        }
        virtual ~work_handle()
        {
        }
        virtual bool run(string& dst_str, string& func_sign, string& func_arg, string& src_str) = 0;
};

class filtration_form_0:virtual public work_handle
{
    public:
        filtration_form_0()
        {
        }
        virtual ~filtration_form_0()
        {
        }
        virtual bool run(string& dst_str, string& func_arg, string& src_str)
        {
            //----
            //
            //end 
            src_str.clear();
        }
};

class get_value_from_jscon_str:virtual public work_handle
{
    public:
        get_value_from_jscon_str()
        {
        }
        virtual ~get_value_from_jscon_str()
        {
        }
        virtual bool run(string& dst_str, string& func_arg, string& src_str)
        {
            dst_str.clear();
        }
};



class work_handle_factory
{
    private:
        map<string,work_handle*> whm;
        work_handle_factory()
        {
            whm["get_value_from_jscon_str"] = new get_value_from_jscon_str();
            whm["filtration_form_0"] = new filtration_form_0();
        }
    public:
        virtual ~work_handle_factory()
        {
        }
        static work_handle_factory& get_instance()
        {
            static work_handle_factory whf;
            return whf;
        }
        work_handle* get_work_handle_from_factory(string& tmp_str)
        {
        }
}



class filtration_func : virtual public func_base
{
    private:
        string m_function_name;
        string m_func_args;
        string m_src_value;
        string m_condition_func;
        string m_value;
        string m_condition_args;
        string m_dst_value;
        string m_key_name;
    protected:
    public:
        filtration_func()
        {
            m_key_name = "filtration";
        }
        virtual ~filtration_func()
        {
        }
        void init();//配置文件
        virtual bool run(arrange_syslog_data_to_table* dst_msg, msg_base* msg)
        {
            //
           return msg->get_one_msg_mem(m_src_value, m_this_mem)
               && work_handle_factory::get_instance().get_work_handle_from_factory(m_function_name)->run(m_dst_value, m_func_args, m_src_value)
               && work_handle_factory::get_instance().get_work_handle_from_factory()->run(m_value, m_condition_value, m_dst_value);
        }
};

class deal_data_func : virtual public func_base
{
    public:
        deal_data_func()
        {
        }
        virtual ~deal_data_func()
        {
        }
        void init();//配置文件
        virtual bool run(arrange_syslog_data_to_table* dst_msg, msg_base* msg)= 0;
};

class output_func : virtual public handle_base
{
    public:
        output_func()
        {
        }
        virtual ~output_func()
        {
        }
        time_t m_space_time;
        void init();//配置文件
        virtual bool run(arrange_syslog_data_to_table* dst_msg, msg_base* msg)= 0;
};

class fflush_time_func : virtual public func_base
{
    public:
        fflush_time_func()
        {
        }
        virtual ~fflush_time_func()
        {
        }
        void init();//配置文件
        virtual bool run(arrange_syslog_data_to_table* dst_msg, msg_base* msg)= 0;
};

class ensure_start_time_func : virtual public handle_base
{
    public:
        ensure_start_time_func()
        {
        }
        virtual ~ensure_start_time_func()
        {
        }
        void init();//配置文件
        virtual bool run(arrange_syslog_data_to_table* dst_msg, msg_base* msg)= 0;
};







#endif  /*_CLEAR_UP_SYSLOG_DATA_H*/
