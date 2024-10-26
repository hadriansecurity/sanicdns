#pragma once

#include <expected.h>
#include <rte_branch_prediction.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <exception>
#include <iostream>
#include <iterator>
#include <optional>
#include <span>

/**
 * @brief Class that provides a RAII wrapper around EAL initialization. Should be instantiated in
 * the main function before anything else.
 */

struct EALGuard {
	static tl::expected<EALGuard, int> init(int argc, char **argv) {
		auto ret = rte_eal_init(argc, argv);
		if (ret == -1)
			return tl::unexpected{rte_errno};
		return EALGuard{};
	}

	~EALGuard() {
		if (_valid)
			rte_eal_cleanup();
	}

	// This type is just a guard, copying is not allowed.
	EALGuard(const EALGuard &) = delete;
	EALGuard &operator=(const EALGuard &) = delete;

	// Move constructor is required for init function.
	EALGuard(EALGuard &&other) : _valid(true) {
		other._valid = false;
	}
	EALGuard &operator=(EALGuard &&other) {
		_valid = true;
		other._valid = false;
		return *this;
	}

private:
	EALGuard() { }
	bool _valid = true;
};

template <typename T>
class RteAllocator {
public:
	using value_type = T;

	RteAllocator() = default;

	T *allocate(std::size_t n) {
		return static_cast<T *>(rte_malloc("RteAllocator", n * sizeof(T), alignof(T)));
	}

	void deallocate(T *p, std::size_t) noexcept {
		rte_free(p);
	}
};

template <typename Elem>
class RTEPktMbuf;

enum class MbufType {
	Raw,
	Pkt
};

/**
 * @brief Class wrapping an RTEMempool. In contrast to RTEPktMempool, this mempool is used to
 * allocate raw types, rather than ones wrapped in an rte_mbuf. Template argument *Elem* determines
 * the size of elements allocated from this mempool. Since this data structure can be shared accross
 * threads, an std::shared_ptr is used to manage ownership.
 */
template <typename Elem, MbufType type = MbufType::Raw>
class RTEMempool {
public:
	/**
	 * @brief Constructs an RTEMempool. If the construction fails an error is printed to stderr
	 * and the application is exited.
	 *
	 * @param name Name of the mempool - MUST be unique.
	 * @param num_elems Number of elements this mempool is able to allocate.
	 * @param cache_size Size of cache of the mempool, usually 0.
	 * @param private_size Size of the private area after the mempool allocation, usually 0.
	 * @param socket_id Socket ID to allocate this mempool to.
	 * @param flags See DPDK documentation for which flags can be set.
	 */
	static tl::expected<RTEMempool, int> init(const std::string &name, size_t num_elems,
	    size_t cache_size, size_t private_size, unsigned int flags,
	    unsigned int socket_id = rte_socket_id())
	requires(type == MbufType::Raw)
	{
		auto ptr = rte_mempool_create(name.c_str(), num_elems, sizeof(Elem), cache_size,
		    private_size, nullptr, nullptr, nullptr, nullptr, socket_id, flags);
		if (!ptr)
			return tl::unexpected{rte_errno};

		return RTEMempool{ptr};
	}

	/**
	 * @brief Construct a new RTEPktMempool. Calls *rte_pktmbuf_pool_create()*.
	 *
	 * When the constructor fails an error message will be printed to stderr, and the
	 * application will be exited.
	 *
	 * @param name Name of the mempool - MUST be unique.
	 * @param pool_size Size of the pool, in number of elements.
	 * @param cache_size Size of the cache to allocate for this mempool, usually 0.
	 * @param priv_size Size of private area for each mbuf, usually 0.
	 * @param socket_id Socket ID to allocate this mempool to.
	 */
	static tl::expected<RTEMempool, int> init(const std::string &name, size_t pool_size,
	    size_t cache_size, size_t priv_size, int socket_id = rte_socket_id())
	requires(type == MbufType::Pkt)
	{
		auto ptr = rte_pktmbuf_pool_create(name.c_str(), pool_size, cache_size, priv_size,
		    sizeof(Elem) + RTE_PKTMBUF_HEADROOM, socket_id);
		if (!ptr)
			return tl::unexpected{rte_errno};

		return RTEMempool{ptr};
	}

	// Delete copy constructors.
	RTEMempool(const RTEMempool &) = delete;
	RTEMempool &operator=(const RTEMempool &) = delete;

	RTEMempool(RTEMempool &&other) {
		ptr_ = other.ptr_;
		other.ptr_ = nullptr;
	}

	RTEMempool &operator=(RTEMempool &&other) {
		std::swap(ptr_, other.ptr_);

		return *this;
	}

	/**
	 * @brief Destructs the mempool if it has a valid pointer.
	 */
	~RTEMempool() {
		// Nothing to do if nullptr
		if (ptr_ == nullptr)
			return;

		rte_mempool_free(ptr_);
		ptr_ = nullptr;
	}

	/**
	 * @brief Returns the number of elements currently in the mempool.
	 */
	size_t count() const {
		return rte_mempool_in_use_count(ptr_);
	}

	/**
	 * @brief Returns the capacity of the mempool.
	 */
	size_t capacity() const {
		return rte_mempool_avail_count(ptr_);
	}

	/**
	 * @brief Get the pointer to the mempool.
	 *
	 * @return std::shared_ptr containing the pointer to the mempool.
	 */
	rte_mempool *get() {
		return ptr_;
	}

private:
	RTEMempool(rte_mempool *ptr) : ptr_(ptr) { }

	rte_mempool *ptr_;
};

template <typename Elem>
struct RTEMbuf : public rte_mbuf {
	template <typename GetElem = Elem, size_t Off = 0>
	requires(sizeof(GetElem) + Off <= sizeof(Elem))
	GetElem &data() {
		GetElem *elem = rte_pktmbuf_mtod_offset(this, GetElem *, Off);
		return *elem;
	}

	template <typename GetElem = Elem, size_t Off = 0>
	requires(sizeof(GetElem) + Off <= sizeof(Elem))
	const GetElem &data() const {
		GetElem *elem = rte_pktmbuf_mtod_offset(this, GetElem *, Off);
		return *elem;
	}
};

namespace _detail {
template <typename Elem, MbufType type>
struct MbufElementHelper;

template <typename Elem>
struct MbufElementHelper<Elem, MbufType::Pkt> {
	MbufElementHelper() : ptr_(nullptr) { }
	MbufElementHelper(RTEMbuf<Elem> *ptr, rte_mempool *) : ptr_(ptr) { }
	RTEMbuf<Elem> *ptr_;
};

template <typename Elem>
struct MbufElementHelper<Elem, MbufType::Raw> {
	MbufElementHelper() : ptr_(nullptr), mempool_(nullptr) { }
	MbufElementHelper(Elem *ptr, rte_mempool *mempool) : ptr_(ptr), mempool_(mempool) { }
	Elem *ptr_;
	rte_mempool *mempool_;
};

} // namespace _detail

template <typename Elem, MbufType type = MbufType::Raw>
class RTEMbufElement : _detail::MbufElementHelper<Elem, type> {
public:
	using value_type =
	    typename std::conditional<type == MbufType::Raw, Elem, RTEMbuf<Elem>>::type;
	using pointer = value_type *;
	using double_pointer = pointer *;

	using reference = value_type &;
	using const_reference = std::add_const_t<reference>;

	static tl::expected<RTEMbufElement, int> init(RTEMempool<Elem, type> &mempool) {
		pointer ptr;
		int res = Alloc(mempool.get(), &ptr);

		if (res)
			return tl::unexpected(res);

		RTEMbufElement ret{mempool.get(), ptr};
		Elem &elem = ret.get_data();
		new (&elem) Elem();

		return ret;
	}

	static tl::expected<RTEMbufElement, int> init(RTEMempool<Elem, type> &mempool,
	    Elem &&elem) {
		pointer ptr;
		int res = Alloc(mempool.get(), &ptr);

		if (res)
			return tl::unexpected(res);

		RTEMbufElement ret{mempool.get(), ptr};
		Elem &new_elem = ret.get_data();
		new (&new_elem) Elem(std::move(elem));

		return ret;
	}

	~RTEMbufElement() {
		if (this->ptr_) {
			Elem &elem = get_data();
			elem.~Elem();
		}

		Free();
	}

	// Disallow copying
	RTEMbufElement(const RTEMbufElement &) = delete;
	RTEMbufElement &operator=(const RTEMbufElement &) = delete;

	RTEMbufElement(RTEMbufElement &&other) {
		this->ptr_ = other.ptr_;
		other.ptr_ = nullptr;
		if constexpr (type == MbufType::Raw)
			this->mempool_ = other.mempool_;
		// Leave other mempool the same
	}

	RTEMbufElement &operator=(RTEMbufElement &&other) {
		std::swap(this->ptr_, other.ptr_);
		if constexpr (type == MbufType::Raw)
			std::swap(this->mempool_, other.mempool_);

		return *this;
	}

	// Check if RTEMbufElement contiains data
	operator bool() const {
		return static_cast<bool>(this->ptr_);
	}

	void release() {
		this->ptr_ = nullptr;
	}

	reference get() {
		return *this->ptr_;
	}
	const_reference get() const {
		return *this->ptr_;
	}

	Elem &get_data()
	requires(type == MbufType::Raw)
	{
		return *this->ptr_;
	}
	Elem &get_data()
	requires(type == MbufType::Pkt)
	{
		return (*this->ptr_).data();
	}

	const Elem &get_data() const
	requires(type == MbufType::Raw)
	{
		return *this->ptr_;
	}
	const Elem &get_data() const
	requires(type == MbufType::Pkt)
	{
		return (*this->ptr_).data();
	}

private:
	using helper_struct = _detail::MbufElementHelper<Elem, type>;

	template <typename U, size_t N, MbufType t>
	friend class RTEMbufArray;

	template <typename U, MbufType t>
	friend class RTERing;

	RTEMbufElement(rte_mempool *mempool, pointer ptr) : helper_struct{ptr, mempool} { }

	static int Alloc(rte_mempool *mempool, double_pointer ptr)
	requires(type == MbufType::Raw)
	{
		return rte_mempool_get(mempool, (void **) ptr);
	}
	static int Alloc(rte_mempool *mempool, double_pointer ptr)
	requires(type == MbufType::Pkt)
	{
		*ptr = (RTEMbuf<Elem> *) rte_pktmbuf_alloc(mempool);
		return *ptr ? 0 : ENOENT;
	}

	void Free()
	requires(type == MbufType::Raw)
	{
		if (this->ptr_)
			rte_mempool_put(this->mempool_, (void *) this->ptr_);
	}
	void Free()
	requires(type == MbufType::Pkt)
	{
		rte_pktmbuf_free(static_cast<rte_mbuf *>(this->ptr_));
	}
};

template <typename Elem, size_t N, MbufType type = MbufType::Raw>
class RTEMbufArray {
public:
	using value_type =
	    typename std::conditional<type == MbufType::Raw, Elem, RTEMbuf<Elem>>::type;
	using owning_value_type = RTEMbufElement<Elem, type>;
	using pointer = value_type *;
	using const_pointer = std::add_const_t<pointer>;
	using double_pointer = pointer *;

	using reference = value_type &;
	using const_reference = std::add_const_t<reference>;

	template <typename T>
	requires(sizeof(T) >= sizeof(Elem))
	static tl::expected<RTEMbufArray, int> init(RTEMempool<T, type> &mempool,
	    const size_t count, const Elem &value) {
		std::array<pointer, N> tmp;
		int res = AllocBulk(count, &tmp.front(), mempool.get());
		if (res)
			return tl::unexpected(res);

		RTEMbufArray ret{mempool.get(),
		    std::span<pointer>(tmp.begin(), tmp.begin() + count)};

		for (size_t i = 0; i < count; i++) {
			Elem &elem = ret.get_data(i);
			new (&elem) Elem{value};
		}

		return ret;
	}

	template <typename T>
	requires(sizeof(T) >= sizeof(Elem))
	static tl::expected<RTEMbufArray, int> init(RTEMempool<T, type> &mempool,
	    const size_t count) {
		std::array<pointer, N> tmp;
		int res = AllocBulk(count, &tmp.front(), mempool.get());
		if (res)
			return tl::unexpected(res);

		RTEMbufArray ret{mempool.get(),
		    std::span<pointer>(tmp.begin(), tmp.begin() + count)};

		for (size_t i = 0; i < ret.size_; i++) {
			Elem &elem = ret.get_data(i);
			new (&elem) Elem();
		}

		return ret;
	}

	template <typename T>
	requires(sizeof(T) >= sizeof(Elem))
	static tl::expected<RTEMbufArray, int> init(RTEMempool<T, type> &mempool) {
		return RTEMbufArray{mempool.get(), {}};
	}

	// For interacting with C API's
	RTEMbufArray(std::span<pointer> span)
	requires(type == MbufType::Pkt)
	    : mempool_(nullptr) // Mempool cannot be passed in this constructor
	{
		assert(span.size() <= N);

		std::copy(span.begin(), span.end(), ptrs.begin());
		size_ = span.size();
	}

	~RTEMbufArray() {
		for (size_t i = 0; i < size_; i++) {
			Elem &elem = get_data(i);
			elem.~Elem();
		}
		FreeAll();

		std::fill(ptrs.begin(), ptrs.end(), nullptr);
		size_ = 0;
	}

	// USE WITH CAUTION -- releases ownership of all elements
	void release() {
		size_ = 0;
		std::fill(ptrs.begin(), ptrs.end(), nullptr);
	}

	// Disallow copying
	RTEMbufArray(const RTEMbufArray &) = delete;
	RTEMbufArray &operator=(const RTEMbufArray &) = delete;

	RTEMbufArray(RTEMbufArray &&other) : ptrs() {
		size_ = other.size_;
		mempool_ = other.mempool_;
		other.size_ = 0;
		// Leave other mempool the same

		std::copy(other.ptrs.begin(), other.ptrs.end(), ptrs.begin());
		std::fill(other.ptrs.begin(), other.ptrs.end(), nullptr);
	}

	RTEMbufArray &operator=(RTEMbufArray &&other) {
		if constexpr (type == MbufType::Raw)
			assert(mempool_ == other.mempool_);

		std::swap(ptrs, other.ptrs);
		std::swap(size_, other.size_);

		return *this;
	}

	[[nodiscard]] RTEMbufArray insert(RTEMbufArray &&other) {
		if constexpr (type == MbufType::Raw)
			assert(mempool_ == other.mempool_);

		const size_t capacity = N - size_;
		const size_t a_size = std::min(capacity, other.size_);
		const size_t b_size = other.size_ - a_size;

		std::copy(other.data(), other.data() + a_size, data() + size_);
		size_ += a_size;

		auto ret = RTEMbufArray(mempool_, std::span(other.data() + a_size, b_size));
		other.release();
		return ret;
	}

	/**
	 * @brief Split the array into two.
	 *
	 * @param index The index into the array to split at. E.g. if index is 7 then first array
	 * will have 7 elements and the second size() - 7.
	 *
	 * @return An std::pair<RTEPktMbufArray, RTEPktMbufArray>.
	 */
	std::pair<RTEMbufArray, RTEMbufArray> split(size_t index) {
		const size_t a_size = std::min(index, size_);
		const size_t b_size = size_ - a_size;

		auto ret = std::make_pair(RTEMbufArray{mempool_, std::span(ptrs.begin(), a_size)},
		    RTEMbufArray{mempool_, std::span(ptrs.begin() + a_size, b_size)});
		release();
		return ret;
	}

	[[nodiscard]] size_t FromSpan(const std::span<pointer> span) {
		auto to_move = std::min(span.size(), N);

		for (size_t i = 0; i < to_move; i++)
			ptrs[i] = span[i];

		size_ = to_move;
		return to_move;
	}

	size_t size() const {
		return size_;
	}

	size_t free_cnt() const {
		return N - size_;
	}

	constexpr size_t capacity() const {
		return N;
	}

	double_pointer data() {
		return &ptrs[0];
	}

	reference operator[](size_t i) {
		return *ptrs[i];
	}

	const_reference operator[](size_t i) const {
		return *ptrs[i];
	}

	Elem &get_data(size_t i)
	requires(type == MbufType::Raw)
	{
		return (*this)[i];
	}
	Elem &get_data(size_t i)
	requires(type == MbufType::Pkt)
	{
		return (*this)[i].data();
	}

	const Elem &get_data(size_t i) const
	requires(type == MbufType::Raw)
	{
		return (*this)[i];
	}
	const Elem &get_data(size_t i) const
	requires(type == MbufType::Pkt)
	{
		return (*this)[i].data();
	}

	template <typename ValueType, typename ItCategory>
	struct BaseIterator;

	using Iterator = BaseIterator<value_type, std::forward_iterator_tag>;
	using ConstIterator = BaseIterator<const value_type, std::forward_iterator_tag>;
	static_assert(std::forward_iterator<Iterator>);
	static_assert(std::forward_iterator<ConstIterator>);

	Iterator begin() {
		return Iterator(ptrs.begin());
	}
	Iterator end() {
		return Iterator(ptrs.begin() + size_);
	}

	// TODO: less ugly conversion??
	ConstIterator begin() const {
		return ConstIterator((const value_type **) (ptrs.begin()));
	}
	ConstIterator end() const {
		return ConstIterator((const value_type **) (ptrs.begin() + size_));
	}

	reference front() {
		return *begin();
	}
	reference back() {
		return *end();
	}

	const_reference front() const {
		return *begin();
	}
	const_reference back() const {
		return *end();
	}

	std::optional<owning_value_type> pop() {
		if (size_ == 0)
			return std::nullopt;
		return owning_value_type{mempool_, ptrs[--size_]};
	}

	[[nodiscard]] std::optional<owning_value_type> push(owning_value_type &&elem) {
		if (size_ >= N)
			return elem;
		ptrs[size_++] = elem.ptr_;
		elem.release();
		return std::nullopt;
	}

private:
	template <typename, MbufType>
	friend class RTERing;

	static int AllocBulk(size_t count, double_pointer ptrs, rte_mempool *mempool)
	requires(type == MbufType::Raw)
	{
		// Only allocate elements when count > 0
		return count ? rte_mempool_get_bulk(mempool, (void **) ptrs, count) : 0;
	}
	static int AllocBulk(size_t count, double_pointer ptrs, rte_mempool *mempool)
	requires(type == MbufType::Pkt)
	{
		// Only allocate elements when count > 0
		return count ? rte_pktmbuf_alloc_bulk(mempool, (rte_mbuf **) ptrs, count) : 0;
	}

	void FreeAll()
	requires(type == MbufType::Raw)
	{
		if (mempool_)
			rte_mempool_put_bulk(mempool_, (void **) &ptrs[0], size_);
		else if (size_)
			spdlog::warn("mbuf array has elements to free without mempool!");
	}
	void FreeAll()
	requires(type == MbufType::Pkt)
	{
		rte_pktmbuf_free_bulk((rte_mbuf **) &ptrs[0], size_);
	}

	RTEMbufArray(rte_mempool *mempool, std::span<pointer> span)
	    : ptrs{}, size_(span.size()), mempool_(mempool) {
		assert(span.size() <= N);

		std::copy(span.begin(), span.end(), ptrs.begin());
	}

	std::array<pointer, N> ptrs;
	size_t size_;
	rte_mempool *mempool_;
};

template <typename Elem, size_t N, MbufType type>
template <typename value_type_, typename iterator_category_>
struct RTEMbufArray<Elem, N, type>::BaseIterator {
	using iterator_category = iterator_category_;
	using difference_type = std::ptrdiff_t;
	using value_type = value_type_;
	using pointer = value_type *;
	using double_pointer = pointer *;
	using reference = value_type &;

	explicit BaseIterator() : ptrs_(nullptr) { }

	BaseIterator(double_pointer ptrs_) : ptrs_(ptrs_) { }

	reference operator*() const {
		return **ptrs_;
	}

	pointer operator->() const {
		return *ptrs_;
	}

	BaseIterator &operator++() {
		ptrs_++;
		return *this;
	}

	BaseIterator operator++(int) {
		BaseIterator tmp = *this;
		ptrs_++;
		return tmp;
	}

	friend bool operator==(const BaseIterator &a, const BaseIterator &b) {
		return a.ptrs_ == b.ptrs_;
	};
	friend bool operator!=(const BaseIterator &a, const BaseIterator &b) {
		return a.ptrs_ != b.ptrs_;
	};

private:
	double_pointer ptrs_;
};

/**
 * @brief A wrapper around an *rte_ring*.
 */
template <typename Elem, MbufType type = MbufType::Raw>
class RTERing {
public:
	using value_type =
	    typename std::conditional<type == MbufType::Raw, Elem, RTEMbuf<Elem>>::type;
	using owning_value_type = RTEMbufElement<Elem, type>;
	using pointer = value_type *;
	using const_pointer = std::add_const_t<pointer>;
	using double_pointer = pointer *;

	using reference = value_type &;
	using const_reference = std::add_const_t<reference>;

	static tl::expected<RTERing, int> init(const std::string &name,
	    RTEMempool<Elem, type> &mempool, size_t num_elems, unsigned int flags,
	    int socket_id = rte_socket_id())
	requires(type == MbufType::Raw)
	{
		rte_ring *ptr = rte_ring_create(name.c_str(), num_elems, socket_id, flags);
		if (!ptr)
			return tl::unexpected(rte_errno);

		return RTERing(ptr, mempool.get());
	}

	static tl::expected<RTERing, int> init(const std::string &name, size_t num_elems,
	    unsigned int flags, int socket_id = rte_socket_id())
	requires(type == MbufType::Pkt)
	{
		rte_ring *ptr = rte_ring_create(name.c_str(), num_elems, socket_id, flags);

		if (!ptr)
			return tl::unexpected(-1);

		return RTERing(ptr, nullptr);
	}

	/**
	 * @brief Deconstructs the ring, and deallocates all the elements still in the ring.
	 */
	~RTERing() {
		if (!ptr_)
			return;

		while (dequeue())
			;

		rte_ring_free(ptr_);
		ptr_ = nullptr;
	}

	/**
	 * @brief Enqueues a single element into the queue.
	 * @param elem The element to enqueue.
	 */
	[[nodiscard]] std::optional<owning_value_type> enqueue(owning_value_type &&elem) {
		void *to_enqueue = &elem.get();
		int res = rte_ring_enqueue(ptr_, to_enqueue);

		// If enqueue was unsuccessful just return the element
		// back
		if (unlikely(res))
			return elem;

		elem.release();
		return std::nullopt;
	}

	template <size_t N>
	[[nodiscard]] RTEMbufArray<Elem, N, type> enqueue_burst(
	    RTEMbufArray<Elem, N, type> &&array) {
		if constexpr (type == MbufType::Raw)
			assert(mempool_ == array.mempool_);

		auto ptr = reinterpret_cast<void **>(array.data());
		auto res = rte_ring_enqueue_burst(ptr_, ptr, array.size(), nullptr);

		auto [enqueued, avail] = array.split(res);
		enqueued.release();
		return std::move(avail);
	}

	/**
	 * @brief Dequeues a single element from the queue.
	 *
	 * @return A std::unique_ptr to the dequeued element.
	 */
	std::optional<owning_value_type> dequeue() {
		pointer elem = nullptr;
		int res = rte_ring_dequeue(ptr_, reinterpret_cast<void **>(&elem));

		if (unlikely(res))
			return std::nullopt;

		return owning_value_type{mempool_, elem};
	}

	template <size_t N>
	RTEMbufArray<Elem, N, type> dequeue_burst(size_t num = N) {
		std::array<typename RTEMbufArray<Elem, N, type>::pointer, N> objs;
		auto objs_ptr = reinterpret_cast<void **>(objs.data());
		auto res = rte_ring_dequeue_burst(ptr_, objs_ptr, num, nullptr);

		return RTEMbufArray<Elem, N, type>{mempool_, std::span{objs.begin(), res}};
	}

	/**
	 * @return The amount of elements enqueued in the ring.
	 */
	size_t count() const {
		return rte_ring_count(ptr_);
	}

	size_t capacity() const {
		return rte_ring_get_capacity(ptr_);
	}

	size_t free_count() const {
		return rte_ring_free_count(ptr_);
	}

	bool empty() const {
		return rte_ring_empty(ptr_);
	}

	// Delete copy constructors.
	RTERing(const RTERing &) = delete;
	RTERing &operator=(const RTERing &) = delete;

	RTERing(RTERing &&other) {
		ptr_ = other.ptr_;
		mempool_ = other.mempool_;
		other.ptr_ = nullptr;
		other.mempool_ = nullptr;
	}

	RTERing &operator=(RTERing &&other) {
		std::swap(ptr_, other.ptr_);
		std::swap(mempool_, other.mempool_);

		return *this;
	}

private:
	RTERing(rte_ring *ptr, rte_mempool *mempool) : ptr_(ptr), mempool_(mempool) { }

	rte_ring *ptr_;
	rte_mempool *mempool_;
};
