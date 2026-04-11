//! Rayon compatibility layer: parallel on native, sequential on WASM.

#[cfg(not(target_arch = "wasm32"))]
pub use rayon::prelude::*;
#[cfg(not(target_arch = "wasm32"))]
pub use rayon::{join, scope};

#[cfg(target_arch = "wasm32")]
pub use self::sequential::*;

#[cfg(target_arch = "wasm32")]
mod sequential {
    // Marker traits matching rayon's API
    pub trait ParallelIterator: Iterator + Sized {
        fn with_min_len(self, _min: usize) -> Self { self }
    }
    pub trait IndexedParallelIterator: ParallelIterator {}

    // Blanket impls: any Iterator is a "ParallelIterator" in sequential mode
    impl<I: Iterator> ParallelIterator for I {}
    impl<I: Iterator> IndexedParallelIterator for I {}

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

    // Vec<T>
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

    // [T]
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

    // Range<usize>
    impl IntoParallelIterator for std::ops::Range<usize> {
        type Iter = std::ops::Range<usize>;
        type Item = usize;
        fn into_par_iter(self) -> Self::Iter { self }
    }

    // (A, B) zip tuple
    impl<A: IntoParallelIterator, B: IntoParallelIterator> IntoParallelIterator for (A, B) {
        type Iter = std::iter::Zip<A::Iter, B::Iter>;
        type Item = (A::Item, B::Item);
        fn into_par_iter(self) -> Self::Iter {
            self.0.into_par_iter().zip(self.1.into_par_iter())
        }
    }

    pub fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA,
        B: FnOnce() -> RB,
    {
        (a(), b())
    }

    pub fn scope<'scope, F, R>(f: F) -> R
    where
        F: FnOnce(&Scope<'scope>) -> R,
    {
        let s = Scope(std::marker::PhantomData);
        f(&s)
    }

    pub struct Scope<'scope>(std::marker::PhantomData<&'scope ()>);
    impl<'scope> Scope<'scope> {
        pub fn spawn<F>(&self, f: F)
        where
            F: FnOnce(&Scope<'scope>) + Send + 'scope,
        {
            f(self);
        }
    }

    pub trait ParallelSlice<T> {
        fn par_chunks_exact(&self, chunk_size: usize) -> std::slice::ChunksExact<'_, T>;
    }
    impl<T> ParallelSlice<T> for [T] {
        fn par_chunks_exact(&self, chunk_size: usize) -> std::slice::ChunksExact<'_, T> {
            self.chunks_exact(chunk_size)
        }
    }
}
