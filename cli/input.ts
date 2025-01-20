export type Arguments = string[]
export type Options = {
  [key: string]: unknown
}

export type Argv = Options & {
  _: Arguments
}
