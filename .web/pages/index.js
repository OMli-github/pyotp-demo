import { Fragment, useEffect, useRef, useState } from "react"
import { useRouter } from "next/router"
import { connect, E, getRefValue, isTrue, preventDefault, processEvent, refs, set_val, uploadFiles } from "/utils/state"
import "focus-visible/dist/focus-visible"
import { Box, Button, Center, Divider, Heading, Input, Text, useColorMode, VStack } from "@chakra-ui/react"
import NextHead from "next/head"


export default function Component() {
  const [state, setState] = useState({"input_text": "", "is_hydrated": false, "results": [], "events": [{"name": "state.hydrate"}], "files": []})
  const [result, setResult] = useState({"state": null, "events": [], "final": true, "processing": false})
  const [notConnected, setNotConnected] = useState(false)
  const router = useRouter()
  const socket = useRef(null)
  const { isReady } = router
  const { colorMode, toggleColorMode } = useColorMode()
  const focusRef = useRef();
  
  // Function to add new events to the event queue.
  const Event = (events, _e) => {
      preventDefault(_e);
      setState(state => ({
        ...state,
        events: [...state.events, ...events],
      }))
  }

  // Function to add new files to be uploaded.
  const File = files => setState(state => ({
    ...state,
    files,
  }))

  // Main event loop.
  useEffect(()=> {
    // Skip if the router is not ready.
    if (!isReady) {
      return;
    }

    // Initialize the websocket connection.
    if (!socket.current) {
      connect(socket, state, setState, result, setResult, router, ['websocket', 'polling'], setNotConnected)
    }

    // If we are not processing an event, process the next event.
    if (!result.processing) {
      processEvent(state, setState, result, setResult, router, socket.current)
    }

    // If there is a new result, update the state.
    if (result.state != null) {
      // Apply the new result to the state and the new events to the queue.
      setState(state => ({
        ...result.state,
        events: [...state.events, ...result.events],
      }))

      // Reset the result.
      setResult(result => ({
        state: null,
        events: [],
        final: true,
        processing: !result.final,
      }))

      // Process the next event.
      processEvent(state, setState, result, setResult, router, socket.current)
    }
  })

  // Set focus to the specified element.
  useEffect(() => {
    if (focusRef.current) {
      focusRef.current.focus();
    }
  })

  // Route after the initial page hydration.
  useEffect(() => {
    const change_complete = () => Event([E('state.hydrate', {})])
    router.events.on('routeChangeComplete', change_complete)
    return () => {
      router.events.off('routeChangeComplete', change_complete)
    }
  }, [router])


  return (
  <Fragment><Fragment>
  <Center sx={{"paddingTop": "5%"}}>
  <VStack sx={{"width": "100%", "padding": "2em"}}>
  <Heading sx={{"fontSize": "2em"}}>
  {`文本解析系统`}
</Heading>
  <Input onBlur={_e => Event([E("state.set_input_text", {value:_e.target.value})], _e)} placeholder="输入需要解析的字符串" sx={{"width": "80%", "padding": "1em"}} type="text"/>
  <Button onClick={_e => Event([E("state.process_text", {})], _e)} sx={{"width": "80%", "bg": "blue", "color": "white"}}>
  {`提交解析`}
</Button>
  <Divider/>
  <Box sx={{"width": "100%"}}>
  {state.results.map((tusyrnmb, i) => (
  <VStack key={i} sx={{"padding": "1em", "border": "1px solid #e0e0e0", "width": "80%", "borderRadius": "8px"}}>
  <Text sx={{"fontWeight": "bold"}}>
  {`输入: {tusyrnmb.text}`}
</Text>
  <Text sx={{"color": "green"}}>
  {`结果: {tusyrnmb.result}`}
</Text>
</VStack>
))}
</Box>
</VStack>
</Center>
  <NextHead>
  <title>
  {`Pynecone App`}
</title>
  <meta content="A Pynecone app." name="description"/>
  <meta content="favicon.ico" property="og:image"/>
</NextHead>
</Fragment>
    </Fragment>
  )
}
