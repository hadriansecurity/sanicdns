#pragma once

#include <spdlog/spdlog.h>

/**
 * @brief Node struct to be added to every object that can appear in a IntrusiveList
 *
 * To be included in every object that the list can manage, see the IntrusiveList documentation for
 * example usage
 *
 * @tparam T Type of the object that manages the node
 */
template <typename T>
struct Node {
public:
	/**
	 * @brief Construct a new Node object
	 *
	 * @param obj_ptr Pointer to the object that the node links to, can be initialized with
	 * `this` in most use cases (when initialized in a class)
	 */
	Node(T* const obj_ptr) : prev(nullptr), next(nullptr), obj_ptr(obj_ptr) { }

	friend void swap(Node& a, Node& b) {
		using std::swap;
		swap(a.prev, b.prev);
		swap(a.next, b.next);
		swap(a.obj_ptr, b.obj_ptr);
	}

	/**
	 * @brief Get a reference to the object that manages the node
	 *
	 * @return T& refrence to the object that manages the node
	 */
	const T& GetDataRef() const {
		return *obj_ptr;
	}
	T& GetDataRef() {
		return *obj_ptr;
	}

	/**
	 * @brief Get the Data Ptr object
	 *
	 * @return T* pointer to the object that manages the node
	 */
	const T* GetDataPtr() const {
		return obj_ptr;
	}
	T* GetDataPtr() {
		return obj_ptr;
	}

	template <typename R, Node<R> R::*Member>
	friend class IntrusiveList;

private:
	Node* prev;
	Node* next;

	T* obj_ptr;
};

/**
 * @brief Doubly linked intrusive list
 *
 * Can be used to link objects in together in a doubly linked list without having the list manage
 * the object. The Node<T> object is used in the managed objects to store the relations
 *
 * ```
 * struct Data
 * {
 *  Data() : node(this), ... { ... }
 *  ...
 *  Node<Data> node;
 * }
 *
 * std::array<N, Data> arr;
 * IntrusiveList<Data, &Data::node> list; // The list object can now be used to link objects in arr
 * ```
 *
 * @tparam T Type of the object that the list has to link
 * @tparam T::*Member Member pointer to the node object in T
 */
template <typename T, Node<T> T::*Member>
class IntrusiveList {
public:
	/**
	 * @brief Construct a new Linked List object
	 *
	 */
	IntrusiveList() : begin_node(nullptr), end_node(nullptr), num_elements(0) {
		begin_node.next = &end_node;
		end_node.prev = &begin_node;
	}

	IntrusiveList(const IntrusiveList&) = delete;
	IntrusiveList& operator=(const IntrusiveList&) = delete;

	friend void swap(IntrusiveList& a, IntrusiveList& b) {
		swap(a, b);
	}

	IntrusiveList(IntrusiveList&& o) : IntrusiveList() {
		swap(*this, o);
	}

	IntrusiveList& operator=(IntrusiveList&& o) {
		swap(*this, o);
		return *this;
	}

	/**
	 * @brief Push element to the back of the timeout list
	 *
	 * @param owner Reference to the owner of the node object that has to be appended to the
	 * list
	 */
	void push_back(T& owner) {
		Node<T>& node = owner.*Member;
		// Skip inserting node into list when it's already inserted
		if (node.prev || node.next)
			return;

		node.next = &end_node;
		node.prev = end_node.prev;
		end_node.prev->next = &node;
		end_node.prev = &node;

		// Track number of elements in list
		num_elements++;
	}

	/**
	 * @brief Delete element from the list
	 *
	 * @param owner Reference to the owner of the node object that has to be deleted from the
	 * list
	 */
	void delete_elem(T& owner) {
		Node<T>& node = owner.*Member;
		// Return if node is not in list altogether
		if (node.prev == nullptr && node.next == nullptr)
			return;

		node.next->prev = node.prev;
		node.prev->next = node.next;

		node.next = node.prev = nullptr;

		// Track number of elements in list
		num_elements--;
	}

	/**
	 * @brief Check if element is present in list
	 *
	 * @param owner Reference to the owner of the node object to check
	 * @return true Element is present
	 * @return false Element is not present
	 */
	bool in_list(const T& owner) const {
		const Node<T>& node = owner.*Member;
		return node.next || node.prev;
	}

	/**
	 * @brief Get number of objects in list
	 *
	 * @return size_t number of objects in list
	 */
	size_t size() const {
		return num_elements;
	}

	template <typename It, typename NodeType>
	struct BaseIterator;

	using Iterator = BaseIterator<T, Node<T>>;
	using ConstIterator = BaseIterator<const T, const Node<T>>;

	Iterator begin() {
		return Iterator(begin_node.next);
	}
	Iterator end() {
		return Iterator(&end_node);
	}

	ConstIterator begin() const {
		return ConstIterator(begin_node.next);
	}
	ConstIterator end() const {
		return ConstIterator(&end_node);
	}

	/**
	 * @brief Erase element by iterator
	 *
	 * @param position Iterator of element that should be deleted
	 * @return Iterator Next element if element has been deleted, argument when it was not
	 * present in the list
	 */
	Iterator erase(Iterator position) {
		delete_elem(*(position++));
		return position;
	}

private:
	Node<T> begin_node;
	Node<T> end_node;
	size_t num_elements;

	static void swap(IntrusiveList& a, IntrusiveList& b) {
		using std::swap;
		swap(a.begin_node, b.begin_node);
		swap(a.end_node, b.end_node);
		swap(a.num_elements, b.num_elements);

		const auto set_stack_nodes = [](IntrusiveList& l) {
			if (l.size() == 0)
				l.begin_node.next = &l.end_node;

			l.begin_node.next->prev = &l.begin_node;
			l.end_node.prev->next = &l.end_node;
		};

		set_stack_nodes(a);
		set_stack_nodes(b);
	}
};

/**
 * @brief Iterator for IntrusiveList
 *
 * @tparam T Type of the object that the list has to link
 * @tparam T::*Member Member pointer to the node object in T
 * @tparam It Base return type for derefence operator and arrow operator (T or const T)
 * @tparam NodeType Type for storing the Node<T> object (Node<T> or const Node<T>)
 */
template <typename T, Node<T> T::*Member>
template <typename It, typename NodeType>
struct IntrusiveList<T, Member>::BaseIterator {
	/**
	 * @brief Construct a new Iterator object
	 *
	 * @param node_ptr Pointer to the node in owner object
	 */
	BaseIterator(NodeType* node_ptr) : node_ptr(node_ptr) { }

	/**
	 * @brief Dereference operator
	 *
	 * @return T& Reference to owner of the node in the iterator
	 */
	It& operator*() const {
		return node_ptr->GetDataRef();
	}

	/**
	 * @brief Arrow operator
	 *
	 * @return T* Pointer to owner of the node in the iterator
	 */
	It* operator->() const {
		return node_ptr->GetDataPtr();
	}

	/**
	 * @brief Front
	 *
	 * @return NodeType& Reference to first element in iterator
	 */
	It& front() const {
		return node_ptr->GetDataRef();
	}

	/**
	 * @brief Prefix increment
	 *
	 * @return Iterator& Reference to the current iterator
	 */
	BaseIterator& operator++() {
		node_ptr = node_ptr->next;
		return *this;
	}

	/**
	 * @brief Postfix increment
	 *
	 * @return Iterator New iterator with previous value
	 */
	BaseIterator operator++(int) {
		Iterator tmp = *this;
		node_ptr = node_ptr->next;
		return tmp;
	}

	friend bool operator==(const BaseIterator& a, const BaseIterator& b) {
		return a.node_ptr == b.node_ptr;
	};
	friend bool operator!=(const BaseIterator& a, const BaseIterator& b) {
		return a.node_ptr != b.node_ptr;
	};

private:
	NodeType* node_ptr;
};
