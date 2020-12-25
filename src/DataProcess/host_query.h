/*
 * host_query.h
 *
 *  Created on: 2020-5-9
 *      Author: andy
 */

#ifndef HOST_QUERY_H_
#define HOST_QUERY_H_

/*************************************************************************
*函数描述：json数据解析函数，用于解析json指令字串
*参数：	 const char * topic mqtt的主题字串
*		 const char * json  json 字串文本

*返回值： int 0解析成功
*			 其他 解析失败
*************************************************************************/
int rxmsg_json_parse(const char * topic, const char * json);

#endif /* HOST_QUERY_H_ */
