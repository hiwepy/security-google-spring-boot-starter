/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.google.exception;

import org.springframework.security.boot.biz.exception.AuthenticationTokenIncorrectException;

/**
 * Google AccessToken Incorrect Exception
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("serial")
public class GoogleAccessTokenIncorrectException extends AuthenticationTokenIncorrectException {
	
	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>GoogleAccessTokenIncorrectException</code> with the
	 * specified message.
	 *
	 * @param msg the detail message
	 */
	public GoogleAccessTokenIncorrectException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>GoogleAccessTokenIncorrectException</code> with the
	 * specified message and root cause.
	 *
	 * @param msg the detail message
	 * @param t root cause
	 */
	public GoogleAccessTokenIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}

}
