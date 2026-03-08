// Copyright 2024 Omni Cyber Solutions LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

"use client";

import { Component, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  handleRetry = () => {
    this.setState({ error: null });
  };

  render() {
    if (this.state.error) {
      if (this.props.fallback) return this.props.fallback;
      return (
        <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
          <div className="p-3 rounded-full bg-red-900/30 mb-3">
            <AlertTriangle className="w-6 h-6 text-red-400" />
          </div>
          <p className="text-sm font-medium text-slate-300">Something went wrong</p>
          <p className="text-xs text-slate-500 mt-1 font-mono max-w-md break-all">
            {this.state.error.message}
          </p>
          <button
            onClick={this.handleRetry}
            className="mt-4 px-4 py-2 text-xs bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg transition-colors"
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
