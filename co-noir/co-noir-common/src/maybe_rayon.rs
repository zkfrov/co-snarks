//! Rayon compatibility layer: parallel on native, sequential on WASM.
//!
//! On native: re-exports rayon's actual parallel iterators.
//! On WASM: provides sequential shims that match rayon's API surface.

#[cfg(not(target_arch = "wasm32"))]
pub use rayon::prelude::*;
#[cfg(not(target_arch = "wasm32"))]
pub use rayon::{join, scope};

#[cfg(target_arch = "wasm32")]
pub use self::sequential::*;

#[cfg(target_arch = "wasm32")]
mod sequential {
    use itertools::Itertools;

    // Marker traits — blanket-impl on all iterators so rayon trait bounds are satisfied
    pub trait ParallelIterator: Iterator + Sized {
        fn with_min_len(self, _min: usize) -> Self { self }
        // rayon's fold takes a factory fn; in sequential mode we just call it once
        fn fold<T, ID, F>(self, identity: ID, fold_op: F) -> Fold<Self, ID, F>
        where
            ID: Fn() -> T,
            F: Fn(T, Self::Item) -> T,
        {
            Fold { iter: self, identity, fold_op }
        }
    }
    pub trait IndexedParallelIterator: ParallelIterator {}

    impl<I: Iterator> ParallelIterator for I {}
    impl<I: Iterator> IndexedParallelIterator for I {}

    // Fold adapter that mimics rayon's Fold (which returns an iterator of partial results)
    pub struct Fold<I, ID, F> {
        iter: I,
        identity: ID,
        fold_op: F,
    }

    impl<I, ID, F, T> Fold<I, ID, F>
    where
        I: Iterator,
        ID: Fn() -> T,
        F: Fn(T, I::Item) -> T,
    {
        pub fn reduce<R>(self, _identity: impl Fn() -> T, _reduce: R) -> T
        where
            R: Fn(T, T) -> T,
        {
            let init = (self.identity)();
            self.iter.fold(init, self.fold_op)
        }
    }

    pub trait IntoParallelIterator {
        type Iter: Iterator<Item = Self::Item>;
        type Item;
        fn into_par_iter(self) -> Self::Iter;
    }
    pub trait IntoParallelRefIterator<'a> {
        type Iter: Iterator<Item = Self::Item>;
        type Item;
        fn par_iter(&'a self) -> Self::Iter;
    }
    pub trait IntoParallelRefMutIterator<'a> {
        type Iter: Iterator<Item = Self::Item>;
        type Item;
        fn par_iter_mut(&'a mut self) -> Self::Iter;
    }

    impl<T> IntoParallelIterator for Vec<T> {
        type Iter = std::vec::IntoIter<T>;
        type Item = T;
        fn into_par_iter(self) -> Self::Iter { self.into_iter() }
    }
    impl<'a, T: 'a> IntoParallelRefIterator<'a> for Vec<T> {
        type Iter = std::slice::Iter<'a, T>;
        type Item = &'a T;
        fn par_iter(&'a self) -> Self::Iter { self.iter() }
    }
    impl<'a, T: 'a> IntoParallelRefMutIterator<'a> for Vec<T> {
        type Iter = std::slice::IterMut<'a, T>;
        type Item = &'a mut T;
        fn par_iter_mut(&'a mut self) -> Self::Iter { self.iter_mut() }
    }
    impl<'a, T: 'a> IntoParallelRefIterator<'a> for [T] {
        type Iter = std::slice::Iter<'a, T>;
        type Item = &'a T;
        fn par_iter(&'a self) -> Self::Iter { self.iter() }
    }
    impl<'a, T: 'a> IntoParallelRefMutIterator<'a> for [T] {
        type Iter = std::slice::IterMut<'a, T>;
        type Item = &'a mut T;
        fn par_iter_mut(&'a mut self) -> Self::Iter { self.iter_mut() }
    }
    impl IntoParallelIterator for std::ops::Range<usize> {
        type Iter = std::ops::Range<usize>;
        type Item = usize;
        fn into_par_iter(self) -> Self::Iter { self }
    }

    // Tuple impls using multizip from itertools
    macro_rules! impl_par_iter_tuple {
        (($($T:ident),+), ($($idx:tt),+)) => {
            impl<'a, $($T: 'a),+> IntoParallelIterator for ($(&'a Vec<$T>,)+) {
                type Iter = Box<dyn Iterator<Item = Self::Item> + 'a>;
                type Item = ($(&'a $T,)+);
                fn into_par_iter(self) -> Self::Iter {
                    Box::new(itertools::izip!($(self.$idx.iter()),+))
                }
            }
            impl<'a, $($T: 'a),+> IntoParallelIterator for ($(&'a [$T],)+) {
                type Iter = Box<dyn Iterator<Item = Self::Item> + 'a>;
                type Item = ($(&'a $T,)+);
                fn into_par_iter(self) -> Self::Iter {
                    Box::new(itertools::izip!($(self.$idx.iter()),+))
                }
            }
        };
    }

    impl_par_iter_tuple!((A, B), (0, 1));
    impl_par_iter_tuple!((A, B, C), (0, 1, 2));
    impl_par_iter_tuple!((A, B, C, D), (0, 1, 2, 3));
    impl_par_iter_tuple!((A, B, C, D, E), (0, 1, 2, 3, 4));
    impl_par_iter_tuple!((A, B, C, D, E, F), (0, 1, 2, 3, 4, 5));
    impl_par_iter_tuple!((A, B, C, D, E, F, G), (0, 1, 2, 3, 4, 5, 6));
    impl_par_iter_tuple!((A, B, C, D, E, F, G, H), (0, 1, 2, 3, 4, 5, 6, 7));
    impl_par_iter_tuple!((A, B, C, D, E, F, G, H, I), (0, 1, 2, 3, 4, 5, 6, 7, 8));
    impl_par_iter_tuple!((A, B, C, D, E, F, G, H, I, J), (0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
    impl_par_iter_tuple!((A, B, C, D, E, F, G, H, I, J, K), (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
    impl_par_iter_tuple!((A, B, C, D, E, F, G, H, I, J, K, L), (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11));

    pub fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
    where A: FnOnce() -> RA, B: FnOnce() -> RB {
        (a(), b())
    }

    pub fn scope<'scope, F, R>(f: F) -> R
    where F: FnOnce(&Scope<'scope>) -> R {
        let s = Scope(std::marker::PhantomData);
        f(&s)
    }

    pub struct Scope<'scope>(std::marker::PhantomData<&'scope ()>);
    impl<'scope> Scope<'scope> {
        pub fn spawn<F>(&self, f: F) where F: FnOnce(&Scope<'scope>) + Send + 'scope {
            f(self);
        }
    }

    pub trait ParallelBridge: Iterator + Sized {
        fn par_bridge(self) -> Self { self }
    }
    impl<I: Iterator> ParallelBridge for I {}

    pub trait ParallelSlice<T> {
        fn par_chunks_exact(&self, chunk_size: usize) -> std::slice::ChunksExact<'_, T>;
    }
    impl<T> ParallelSlice<T> for [T] {
        fn par_chunks_exact(&self, chunk_size: usize) -> std::slice::ChunksExact<'_, T> {
            self.chunks_exact(chunk_size)
        }
    }
}
