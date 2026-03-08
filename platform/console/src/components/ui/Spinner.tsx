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

type Size = "sm" | "md" | "lg";

const SIZE_CLASSES: Record<Size, string> = {
  sm: "w-3 h-3 border",
  md: "w-5 h-5 border-2",
  lg: "w-8 h-8 border-2",
};

export function Spinner({ size = "md" }: { size?: Size }) {
  return (
    <span
      className={`inline-block rounded-full border-current border-r-transparent animate-spin ${SIZE_CLASSES[size]}`}
      aria-label="Loading"
    />
  );
}
