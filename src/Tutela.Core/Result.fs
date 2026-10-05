namespace Tutela.Core

/// Result computation expression and traversal helpers. Pure; no external effects.
[<AutoOpen>]
module ResultBuilder =
    type ResultCE() =
        member _.Return x = Ok x
        member _.ReturnFrom (r: Result<_, _>) = r
        member _.Bind (r, f) = Result.bind f r
        member _.Zero () = Ok ()
        member _.Delay f = f
        member _.Run f = f ()

    /// `result { let! x = ... }` short-circuits on the first Error.
    let result = ResultCE()

module ResultList =
    /// Converts a list of results into a result of a list, preserving order and
    /// returning the first error encountered.
    let sequence (results: Result<'a, 'e> list) : Result<'a list, 'e> =
        List.foldBack
            (fun r acc ->
                match r, acc with
                | Ok x, Ok xs -> Ok (x :: xs)
                | Error e, _ -> Error e
                | _, Error e -> Error e)
            results (Ok [])

    let traverse f xs = xs |> List.map f |> sequence
