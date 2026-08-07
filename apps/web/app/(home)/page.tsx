/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

"use client";

import { useEffect } from "react";
// plane imports
import { API_BASE_URL } from "@plane/constants";

export default function HomePage() {
  useEffect(() => {
    window.location.replace(`${API_BASE_URL}/auth/keycloak/`);
  }, []);

  return null;
}
