/*
 * BaseAccessControl.h
 *
 *  Created on: May 25, 2023
 *      Author: nbarros
 */

#ifndef SERVER_INCLUDE_BASEACCESSCONTROL_H_
#define SERVER_INCLUDE_BASEACCESSCONTROL_H_

#include <open62541.h>


class BaseAccessControl
{
public:
  BaseAccessControl () {}
  virtual ~BaseAccessControl () {}

  virtual void link_callbacks(UA_Server *s) = 0;

protected:

private:

  BaseAccessControl (const BaseAccessControl &other) = delete;
  BaseAccessControl& operator= (const BaseAccessControl &other) = delete;
  BaseAccessControl (BaseAccessControl &&other) = delete;
  BaseAccessControl& operator= (BaseAccessControl &&other) = delete;
};



#endif /* SERVER_INCLUDE_ACCESSCONTROL_H_ */
